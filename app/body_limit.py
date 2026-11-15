"""Bound request bodies before FastAPI parses them."""

import json


class BodyLimitMiddleware:
    def __init__(self, app, max_bytes=16384):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if not (
            scope["type"] == "http"
            and scope.get("method") == "POST"
            and scope.get("path") == "/v1/security/evaluate"
        ):
            return await self.app(scope, receive, send)

        async def reject():
            body = json.dumps({
                "detail": "Request body too large"
            }).encode()
            await send({
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"cache-control", b"no-store"),
                ],
            })
            await send({
                "type": "http.response.body",
                "body": body,
            })

        chunks = []
        total = 0

        for name, value in scope.get("headers", []):
            if name.lower() == b"content-length":
                try:
                    if int(value) > self.max_bytes:
                        return await reject()
                except ValueError:
                    pass

        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue

            chunk = message.get("body", b"")
            total += len(chunk)

            if total > self.max_bytes:
                return await reject()

            chunks.append(chunk)

            if not message.get("more_body", False):
                break

        first = True

        async def replay():
            nonlocal first
            if first:
                first = False
                return {
                    "type": "http.request",
                    "body": b"".join(chunks),
                    "more_body": False,
                }
            return await receive()

        return await self.app(scope, replay, send)
