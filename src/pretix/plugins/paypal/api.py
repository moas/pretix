import hashlib
import json

from django.core.cache import cache
from paypalrestsdk.api import Api as VendorApi


class Api(VendorApi):
    def get_token_hash(self, authorization_code=None, refresh_token=None, headers=None):
        if not authorization_code and not refresh_token:
            checksum = hashlib.sha256(self.basic_auth().encode()).hexdigest()
            cache_key_hash = f'pretix_paypal_token_hash_{checksum}'
            cache_key_request_at = f'pretix_paypal_token_request_at_{checksum}'
            token_hash = cache.get(cache_key_hash)
            if token_hash:
                token_request_at = cache.get(cache_key_request_at)
                if token_request_at:
                    self.token_hash = json.loads(token_hash)
                    self.token_request_at = token_request_at
                    self.validate_token_hash()
                    if self.token_hash is not None:
                        return self.token_hash

            t = super().get_token_hash(authorization_code, refresh_token, headers)

            if self.token_hash:
                cache.set(cache_key_hash, json.dumps(self.token_hash), 3600 * 4)
                cache.set(cache_key_request_at, self.token_request_at, 3600 * 4)

            return t

        return super().get_token_hash(authorization_code, refresh_token, headers)
