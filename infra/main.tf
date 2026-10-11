terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 6.0" }
  }
}
variable "project_id" { type = string }
variable "bucket_name" { type = string }
provider "google" {
  project = var.project_id
  region  = "us-central1"
}
# Optional deployment example; not applied or validated in a cloud account.
resource "google_storage_bucket" "evidence" {
  name                        = var.bucket_name
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  versioning { enabled = true }
}
resource "google_service_account" "analyst" {
  account_id   = "sentinel-evidence-reader"
  display_name = "Sentinel evidence reader"
}
resource "google_storage_bucket_iam_member" "reader" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.analyst.email}"
}
