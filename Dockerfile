FROM python:3.6-alpine
MAINTAINER Elazar Broad "elazar.broad@fireeye.com"
COPY . /opt/hxtool
WORKDIR /opt/hxtool
# TODO: should be converted to a script
RUN apk add --no-cache libstdc++ \ 
&& apk add --no-cache --virtual .build-dependencies build-base gcc abuild binutils binutils-doc gcc-doc \
&& pip install --no-cache-dir -r requirements.txt \
&& find /usr/local/lib/python3.6/site-packages/pandas -type f -name *.so -exec strip {} \; \
&& find /usr/local/lib/python3.6/site-packages/numpy -type f -name *.so -exec strip {} \; \
&& apk del .build-dependencies \
&& rm -rf /root/.cache
EXPOSE 8080:8080
ENTRYPOINT ["python", "hxtool.py"]