FROM python:3.11-alpine

WORKDIR /app

COPY --chmod=550 httproxy.py /usr/local/bin/httproxy
COPY --chmod=550 start_httproxy.sh /usr/local/bin/start-httproxy

RUN apk add --no-cache bash
RUN --mount=type=bind,source=requirements.txt,target=requirements.txt \
    pip install --no-cache-dir -r requirements.txt

CMD ["start-httproxy"]
