"""SentinelAPI: isolated educational security lab; no scanner or remediation executor."""
import json
import logging
import os
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import JSON, Float, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.middleware.cors import CORSMiddleware

log = logging.getLogger("sentinel.audit")
logging.basicConfig(level=logging.INFO, format="%(message)s")

@dataclass
class Settings:
    database_url: str = "sqlite:///.state/sentinel.db"
    public_key: str = ""
    issuer: str = "sentinel-local"
    audience: str = "sentinel-api"
    jwks_url: str = ""
    redis_url: str = ""
    rate_limit: int = 30
    rate_window: int = 60
    auth_threshold: int = 5
    access_threshold: int = 3
    detection_window: int = 60
    max_body: int = 16384
    clock: object = time.time

    @classmethod
    def env(cls):
        path = Path(os.getenv("JWT_PUBLIC_KEY_FILE", ".state/public.pem"))
        return cls(database_url=os.getenv("DATABASE_URL", "sqlite:///.state/sentinel.db"),
                   public_key=path.read_text() if path.exists() else "",
                   issuer=os.getenv("JWT_ISSUER", "sentinel-local"),
                   audience=os.getenv("JWT_AUDIENCE", "sentinel-api"),
                   jwks_url=os.getenv("JWKS_URL", ""), redis_url=os.getenv("REDIS_URL", ""))

class Base(DeclarativeBase): pass

class Payment(Base):
    __tablename__ = "payments"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    tenant: Mapped[str] = mapped_column(String)
    amount: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String)

class Event(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[float] = mapped_column(Float)
    tenant: Mapped[str] = mapped_column(String)
    actor: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String)
    correlation: Mapped[str] = mapped_column(String)
    detail: Mapped[dict] = mapped_column(JSON)

class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    created: Mapped[float] = mapped_column(Float)
    tenant: Mapped[str] = mapped_column(String)
    actor: Mapped[str] = mapped_column(String)
    rule: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    assignee: Mapped[str] = mapped_column(String, default="")
    notes: Mapped[str] = mapped_column(String, default="")
    evidence: Mapped[list] = mapped_column(JSON)

RULES = {
 "AUTH-001": {"kind":"auth_failure", "severity":"medium", "rationale":"Repeated invalid authentication may indicate credential abuse.", "guidance":"Review gateway source evidence and identity provider logs. Anonymous requests are not attributed to a verified tenant."},
 "ACCESS-001": {"kind":"access_denied", "severity":"high", "rationale":"A verified identity repeatedly requested records outside its tenant.", "guidance":"Inspect correlated requests, verify intended access, and review session and permissions."},
 "RATE-001": {"kind":"rate_limited", "severity":"medium", "rationale":"A verified identity exceeded the configured request allowance.", "guidance":"Check legitimate client retries before escalating."},
 "ADMIN-001": {"kind":"admin_action", "severity":"low", "rationale":"Privileged incident changes require an auditable review trail.", "guidance":"Verify the change and its approver."},
 "EXPORT-001": {"kind":"bulk_read", "severity":"medium", "rationale":"Repeated full payment-list reads can indicate unusual retrieval.", "guidance":"Compare with expected workflow and inspect request timing."},
}

class RateLimiter:
    def __init__(self, settings):
        self.s = settings; self.entries = defaultdict(deque); self.lock = Lock(); self.redis = None
        if settings.redis_url:
            import redis
            self.redis = redis.Redis.from_url(settings.redis_url)
    def allowed(self, key):
        now = self.s.clock()
        if self.redis:
            # Atomic fixed window with TTL; Redis failures fail closed.
            script = "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end; return n"
            try:
                n = self.redis.eval(script, 1, "sentinel:rate:" + key + ":" + str(int(now)//self.s.rate_window), self.s.rate_window)
                return n <= self.s.rate_limit
            except Exception as exc:
                raise HTTPException(503, "Rate-limit service unavailable") from exc
        with self.lock:
            q=self.entries[key]
            while q and q[0] <= now-self.s.rate_window: q.popleft()
            if len(q) >= self.s.rate_limit: return False
            q.append(now); return True

class Detection:
    def __init__(self, settings, sessions):
        self.s=settings; self.sessions=sessions; self.lock=Lock()
    def record(self, request, kind, actor="anonymous", tenant="unverified", **detail):
        # Whitelist evidence fields. Never record raw tokens, payloads, or credentials.
        safe={k:v for k,v in detail.items() if k in {"resource", "reason", "incident", "count"}}
        event={"id":str(uuid.uuid4()),"timestamp":self.s.clock(),"tenant":tenant,"actor":actor,
               "kind":kind,"correlation":getattr(request.state,"correlation",str(uuid.uuid4())),"detail":safe}
        log.info(json.dumps(event))
        with self.lock, self.sessions() as db:
            db.add(Event(**event)); db.commit()
            for rule, spec in RULES.items():
                if spec["kind"] != kind: continue
                threshold={"AUTH-001":self.s.auth_threshold,"ACCESS-001":self.s.access_threshold,"EXPORT-001":4}.get(rule,1)
                ids=list(db.scalars(select(Event.id).where(Event.kind==kind, Event.actor==actor, Event.tenant==tenant, Event.timestamp>event["timestamp"]-self.s.detection_window).order_by(Event.timestamp)))
                if len(ids)<threshold: continue
                recent=db.scalar(select(Incident).where(Incident.actor==actor, Incident.tenant==tenant, Incident.rule==rule, Incident.created>event["timestamp"]-self.s.detection_window))
                if recent:
                    recent.evidence=ids
                else:
                    db.add(Incident(id=str(uuid.uuid4()),created=event["timestamp"],tenant=tenant,actor=actor,rule=rule,severity=spec["severity"],status="open",evidence=ids,notes="",assignee=""))
                db.commit()
        return event["id"]

class UpdateIncident(BaseModel):
    status: str = Field(pattern="^(open|investigating|resolved)$")
    assignee: str = Field(default="", max_length=80)
    notes: str = Field(default="", max_length=2000)

class UpdatePayment(BaseModel):
    status: str = Field(pattern="^(pending|settled|cancelled)$")

bearer = HTTPBearer(auto_error=False)

def create_app(settings=None):
    s=settings or Settings.env()
    Path('.state').mkdir(exist_ok=True)
    args={"check_same_thread":False} if s.database_url.startswith("sqlite") else {}
    engine=create_engine(s.database_url,connect_args=args)
    Base.metadata.create_all(engine)
    sessions=sessionmaker(engine,expire_on_commit=False)
    with sessions() as db:
        if not db.get(Payment,"pay-a-001"):
            db.add_all([Payment(id="pay-a-001",tenant="tenant-a",amount=12500,status="pending"),Payment(id="pay-b-001",tenant="tenant-b",amount=8700,status="settled")]); db.commit()
    app=FastAPI(title="SentinelAPI Security Lab",version="1.0.0")
    app.state.sessions=sessions; app.state.engine=engine
    detection=Detection(s,sessions); limiter=RateLimiter(s)
    jwks=jwt.PyJWKClient(s.jwks_url,cache_jwk_set=True,lifespan=300) if s.jwks_url else None
    app.add_middleware(CORSMiddleware,allow_origins=["http://localhost:8080"],allow_methods=["GET","PATCH"],allow_headers=["Authorization","Content-Type"])

    @app.middleware("http")
    async def guard(request, call_next):
        request.state.correlation=str(uuid.uuid4())
        # Count streamed bytes rather than trusting Content-Length.
        total=0; body=bytearray()
        async for part in request.stream():
            total+=len(part)
            if total>s.max_body:
                return JSONResponse({"detail":"Payload too large"},status_code=413,headers={"X-Correlation-ID":request.state.correlation})
            body.extend(part)
        request._body=bytes(body)
        response=await call_next(request)
        response.headers["X-Correlation-ID"]=request.state.correlation
        response.headers["X-Content-Type-Options"]="nosniff"
        response.headers["Cache-Control"]="no-store"
        return response

    def identity(request:Request, credentials:HTTPAuthorizationCredentials|None=Depends(bearer)):
        try:
            if not credentials: raise jwt.InvalidTokenError()
            key=jwks.get_signing_key_from_jwt(credentials.credentials).key if jwks else s.public_key
            if not key: raise HTTPException(503,"Configure a verification key before using the lab")
            claims=jwt.decode(credentials.credentials,key,algorithms=["RS256"],issuer=s.issuer,audience=s.audience,
                              options={"require":["exp","iat","sub","iss","aud","tenant"]})
            if not isinstance(claims["sub"],str) or not claims["sub"] or claims["tenant"] not in {"tenant-a","tenant-b"}:
                raise jwt.InvalidTokenError()
            roles=claims.get("realm_access",{}).get("roles",claims.get("roles",[]))
            if not isinstance(roles,list) or not all(isinstance(x,str) for x in roles): raise jwt.InvalidTokenError()
            claims["roles"]=roles
        except HTTPException: raise
        except jwt.PyJWKClientConnectionError as exc:
            raise HTTPException(503,"Identity provider unavailable") from exc
        except (jwt.PyJWTError, ValueError, TypeError, AttributeError):
            detection.record(request,"auth_failure",reason="invalid_or_missing_token")
            raise HTTPException(401,"Invalid or missing access token",headers={"WWW-Authenticate":"Bearer"})
        if not limiter.allowed(claims["tenant"]+":"+claims["sub"]):
            detection.record(request,"rate_limited",claims["sub"],claims["tenant"],reason="request_allowance_exceeded")
            raise HTTPException(429,"Request allowance exceeded",headers={"Retry-After":str(s.rate_window)})
        return claims

    def analyst(claims=Depends(identity)):
        if not {"analyst","admin"}.intersection(claims["roles"]): raise HTTPException(403,"Analyst role required")
        return claims

    def payment_resource(payment_id,request,claims,db):
        payment=db.get(Payment,payment_id)
        if not payment or payment.tenant!=claims["tenant"]:
            detection.record(request,"access_denied",claims["sub"],claims["tenant"],resource=payment_id,reason="object_scope_denied")
            raise HTTPException(404,"Payment not found")
        return payment

    @app.get("/health")
    def health(): return {"status":"ok","mode":"isolated-lab"}

    @app.get("/payments/{payment_id}")
    def payment(payment_id:str,request:Request,claims=Depends(identity)):
        with sessions() as db:
            p=payment_resource(payment_id,request,claims,db)
            detection.record(request,"payment_read",claims["sub"],claims["tenant"],resource=p.id)
            return {"id":p.id,"tenant":p.tenant,"amount_cents":p.amount,"status":p.status}

    @app.patch("/payments/{payment_id}")
    def update_payment(payment_id:str,data:UpdatePayment,request:Request,claims=Depends(identity)):
        with sessions() as db:
            p=payment_resource(payment_id,request,claims,db); p.status=data.status; db.commit()
            detection.record(request,"payment_update",claims["sub"],claims["tenant"],resource=p.id)
            return {"id":p.id,"status":p.status}

    @app.get("/payments")
    def payments(request:Request,claims=Depends(identity)):
        with sessions() as db:
            rows=db.scalars(select(Payment).where(Payment.tenant==claims["tenant"])).all()
            detection.record(request,"bulk_read",claims["sub"],claims["tenant"],count=len(rows))
            return [{"id":p.id,"amount_cents":p.amount,"status":p.status} for p in rows]

    def scope(query,model,claims):
        return query if "admin" in claims["roles"] else query.where(model.tenant==claims["tenant"])

    @app.get("/incidents")
    def incidents(claims=Depends(analyst)):
        with sessions() as db:
            rows=db.scalars(scope(select(Incident).order_by(Incident.created.desc()).limit(100),Incident,claims)).all()
            return [{"id":r.id,"created":r.created,"tenant":r.tenant,"actor":r.actor,"rule":r.rule,"rule_version":"1.0.0","severity":r.severity,"status":r.status,"assignee":r.assignee,"notes":r.notes,"evidence_ids":r.evidence,**RULES[r.rule]} for r in rows]

    @app.get("/events")
    def events(claims=Depends(analyst)):
        with sessions() as db:
            rows=db.scalars(scope(select(Event).order_by(Event.timestamp.desc()).limit(200),Event,claims)).all()
            return [{"id":r.id,"timestamp":r.timestamp,"tenant":r.tenant,"actor":r.actor,"kind":r.kind,"correlation":r.correlation,"detail":r.detail} for r in rows]

    @app.patch("/incidents/{incident_id}")
    def update_incident(incident_id:str,data:UpdateIncident,request:Request,claims=Depends(analyst)):
        with sessions() as db:
            row=db.get(Incident,incident_id)
            if not row or ("admin" not in claims["roles"] and row.tenant!=claims["tenant"]): raise HTTPException(404,"Incident not found")
            row.status=data.status;row.assignee=data.assignee;row.notes=data.notes;db.commit()
            detection.record(request,"admin_action",claims["sub"],claims["tenant"],incident=incident_id)
            return {"id":row.id,"status":row.status}

    @app.get("/rules")
    def rules(claims=Depends(analyst)):
        return {"version":"1.0.0","window_seconds":s.detection_window,"rules":RULES}
    return app

app=create_app()
