FROM python:3.11-slim
WORKDIR /app
COPY gateway.py .
RUN pip install flask
CMD ["python", "gateway.py"]
