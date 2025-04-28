FROM python:3.11-alpine

WORKDIR /app

COPY httproxy.py .
COPY requirements.txt .
COPY start_httproxy.sh .

RUN apk add --no-cache bash
RUN pip install --no-cache-dir -r requirements.txt

CMD ["/bin/bash", "start_httproxy.sh"]
