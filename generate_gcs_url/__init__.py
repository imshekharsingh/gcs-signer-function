import os
import base64
import hmac
import hashlib
import logging
import requests
import urllib.parse
from datetime import datetime, timedelta
import azure.functions as func

GCS_ACCESS_KEY = os.environ["GCS_ACCESS_KEY"]
GCS_SECRET_KEY = os.environ["GCS_SECRET_KEY"]
GCS_BUCKET = os.environ["GCS_BUCKET"]
GCS_CUSTOM_HOST = os.environ.get("GCS_CUSTOM_HOST", "storage.googleapis.com")

def generate_signed_url(object_name):
    expiration = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    string_to_sign = f"GET\n\n\n{expiration}\n/{GCS_BUCKET}/{object_name}"

    raw_signature = hmac.new(GCS_SECRET_KEY.encode(), string_to_sign.encode(), hashlib.sha1).digest()
    signature = urllib.parse.quote(base64.b64encode(raw_signature))

    return (
        f"https://{GCS_CUSTOM_HOST}/{GCS_BUCKET}/{object_name}"
        f"?GoogleAccessId={GCS_ACCESS_KEY}&Expires={expiration}&Signature={signature}"
    )

def main(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
    object_path = req.route_params.get("path", "").strip("/")

    # Adding 400 status code logging
    if not object_path:
        logging.warning("400: Missing object path in request.")
        logging.debug(f"Request URL: {req.url}")
        logging.debug(f"Route params: {req.route_params}")
        return func.HttpResponse("Missing object path", status_code=400)

    signed_url = generate_signed_url(object_path)
    logging.info(f"Signed URL generated: {signed_url}")

    try:
        resp = requests.get(signed_url)

        if resp.status_code == 400:
            logging.error("400: GCS returned Bad Request.")
            logging.debug(f"Signed URL: {signed_url}")
            logging.debug(f"GCS Response Headers: {resp.headers}")
            logging.debug(f"GCS Response Body: {resp.text}")

        return func.HttpResponse(
            body=resp.content,
            status_code=resp.status_code,
            headers={
                "Content-Type": resp.headers.get("Content-Type", "application/octet-stream")
            }
        )
    except Exception as e:
        logging.exception("Exception occurred while fetching object from GCS.")
        return func.HttpResponse("Internal server error", status_code=500)