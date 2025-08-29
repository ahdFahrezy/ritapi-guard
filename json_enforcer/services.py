import json
from jsonschema import validate, ValidationError
from .models import JsonSchema


class JsonEnforcerService:

    @staticmethod
    def validate_payload(endpoint: str, payload_raw):
        """
        Validate JSON payload (even if malformed).
        - Try to parse payload_raw into dict
        - Validate against schema if available
        """
        # 1. Try to parse payload
        try:
            if isinstance(payload_raw, (str, bytes)):
                payload = json.loads(payload_raw)
            elif isinstance(payload_raw, dict):
                payload = payload_raw
            else:
                return {"valid": False, "message": "Unsupported payload type"}
        except json.JSONDecodeError as e:
            return {"valid": False, "message": f"Malformed JSON: {e}"}

        # 2. Check schema from DB
        try:
            schema = JsonSchema.objects.filter(endpoint=endpoint, is_active=True).first()
            if not schema:
                return {"valid": True, "message": "No schema configured, skipped validation"}
            
            schema_data = schema.schema_json
            if isinstance(schema_data, str):  # kalau masih string, parse dulu
                schema_data = json.loads(schema_data)

            validate(instance=payload, schema=schema_data)
            return {"valid": True, "message": "Payload is valid"}
        except ValidationError as e:
            return {"valid": False, "message": f"Schema validation failed: {e.message}"}
        except Exception as e:
            return {"valid": False, "message": f"Unexpected error: {e}"}
