import os
import base64
import hmac
import hashlib
from datetime import datetime, timedelta
import azure.functions as func

GCS_ACCESS_KEY = os.environ["GCS_ACCESS_KEY"]
GCS_SECRET_KEY = os.environ["GCS_SECRET_KEY"]
GCS_BUCKET = os.environ["GCS_BUCKET"]

def generate_signed_url(object_name):
    expiration = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    string_to_sign = f"GET\n\n\n{expiration}\n/{GCS_BUCKET}/{object_name}"
    signature = base64.b64encode(
        hmac.new(GCS_SECRET_KEY.encode(), string_to_sign.encode(), hashlib.sha1).digest()
    ).decode()

    return (
        f"https://storage.googleapis.com/{GCS_BUCKET}/{object_name}"
        f"?GoogleAccessId={GCS_ACCESS_KEY}&Expires={expiration}&Signature={signature}"
    )

def main(req: func.HttpRequest) -> func.HttpResponse:
    object_path = req.route_params.get("path")
    if not object_path:
        return func.HttpResponse("Missing object path", status_code=400)

    signed_url = generate_signed_url(object_path)
    return func.HttpResponse(status_code=302, headers={"Location": signed_url})