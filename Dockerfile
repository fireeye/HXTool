FROM python:3.6-slim
LABEL maintainer="Elazar Broad <elazar.broad@fireeye.com>"
WORKDIR /opt/hxtool
# TODO: should be converted to a script
COPY requirements.txt ./
RUN apt-get update && apt-get install -y dbus gnome-keyring \
&& pip install --no-cache-dir pymongo psycopg2-binary pydbus \
&& pip install --no-cache-dir -r requirements.txt \
&& rm -rf /root/.cache
COPY . /opt/hxtool
VOLUME /opt/hxtool/data /opt/hxtool/bulkdownload /opt/hxtool/log
EXPOSE 8080/tcp
ENTRYPOINT ["/bin/sh", "docker-entrypoint.sh"]
