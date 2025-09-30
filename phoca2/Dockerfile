FROM python:3.7

ADD . ./

RUN pip install -r requirements.txt
RUN apt update && apt install jq -y
ENTRYPOINT ["python", "./phoca.py"]
