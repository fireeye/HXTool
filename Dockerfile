FROM python:3.6
MAINTAINER Elazar Broad "elazar.broad@fireeye.com"
COPY src /hxtool
WORKDIR /hxtool
RUN pip install -r requirements.txt
ENTRYPOINT ["python"]
CMD ["hxtool.py"]