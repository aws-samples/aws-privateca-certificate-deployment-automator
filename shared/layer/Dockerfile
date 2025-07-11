# Multi-architecture Lambda layer build for cryptography
FROM public.ecr.aws/lambda/python:3.12

# Install build dependencies
RUN dnf update -y && \
    dnf install -y gcc openssl-devel libffi-devel && \
    dnf clean all

# Create layer directory structure
RUN mkdir -p /opt/python

# Copy and install from requirements file
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --target /opt/python -r /tmp/requirements.txt

# Copy shared utilities to layer
COPY models.py /opt/python/
COPY error_handler.py /opt/python/

# Create layer zip
WORKDIR /opt
RUN zip -r /tmp/lambda-layer.zip python/

# Copy to output
CMD ["cp", "/tmp/lambda-layer.zip", "/output/"]