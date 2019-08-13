FROM python:3.6-alpine
LABEL maintainer="Elazar Broad <elazar.broad@fireeye.com>"
WORKDIR /opt/hxtool
# TODO: should be converted to a script
COPY requirements.txt ./
RUN apk add --no-cache libstdc++ \ 
&& apk add --no-cache --virtual .build-dependencies build-base gcc abuild binutils binutils-doc gcc-doc postgresql-dev python3-dev \
&& pip install numpy psycopg2 --no-cache-dir \
&& pip install --no-cache-dir -r requirements.txt \
&& find /usr/local/lib/python3.6/site-packages/pandas -type f -name *.so -exec strip {} \; \
&& find /usr/local/lib/python3.6/site-packages/numpy -type f -name *.so -exec strip {} \; \
&& apk del .build-dependencies \
&& rm -rf /root/.cache
COPY . /opt/hxtool
VOLUME /opt/hxtool/data /opt/hxtool/bulkdownload /opt/hxtool/log
EXPOSE 8080/tcp
ENTRYPOINT ["python", "hxtool.py"]