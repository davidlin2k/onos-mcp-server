from typing import Any, Dict, List, Optional
import os
import httpx

# Configuration
ONOS_API_BASE = os.environ.get("ONOS_API_BASE", "http://localhost:8181/onos/v1")
ONOS_USERNAME = os.environ.get("ONOS_USERNAME", "onos")
ONOS_PASSWORD = os.environ.get("ONOS_PASSWORD", "rocks")
HTTP_TIMEOUT = 30.0  # seconds


async def make_onos_request(
    method: str,
    path: str,
    json: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Make a request to the ONOS REST API with proper authentication and error handling."""
    url = f"{ONOS_API_BASE}{path}"
    auth = (ONOS_USERNAME, ONOS_PASSWORD)

    async with httpx.AsyncClient() as client:
        try:
            if method.lower() == "get":
                response = await client.get(
                    url, auth=auth, params=params, timeout=HTTP_TIMEOUT
                )
            elif method.lower() == "post":
                response = await client.post(
                    url, auth=auth, json=json, timeout=HTTP_TIMEOUT
                )
            elif method.lower() == "put":
                response = await client.put(
                    url, auth=auth, json=json, timeout=HTTP_TIMEOUT
                )
            elif method.lower() == "delete":
                response = await client.delete(url, auth=auth, timeout=HTTP_TIMEOUT)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            return response.json() if response.content else {}
        except httpx.HTTPStatusError as e:
            error_msg = f"ONOS API error: {e.response.status_code} - {e.response.text}"
            raise ValueError(error_msg)
        except Exception as e:
            raise ValueError(f"Error connecting to ONOS: {str(e)}")
