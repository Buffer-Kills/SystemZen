FROM ubuntu:focal

RUN apt-get update \ 
    && apt-get upgrade -y \
    && apt-get install -y git python3 python3-dev python3-pip python-is-python3 libpcap-dev build-essential procps schedtool cron \
    && pip3 install pcapy-ng \
    && git clone --depth=1 https://github.com/stamparm/.git /opt/systemzen \
    && python /opt/systemzen/core/update.py

RUN touch /var/log/cron.log

RUN (echo '*/1 * * * * if [ -n "$(ps -ef | grep -v grep | grep server.py)" ]; then : ; else python /opt/systemzen/server.py -c /opt/systemzen/maltrail.conf; fi >> /var/log/cron.log') | crontab
RUN (crontab -l ; echo '*/1 * * * * if [ -n "$(ps -ef | grep -v grep | grep sensor.py)" ]; then : ; else python /opt/systemzen/sensor.py -c /opt/systemzen/maltrail.conf; fi >> /var/log/cron.log') | crontab
RUN (crontab -l ; echo '0 1 * * * cd /opt/systemzen && git pull') | crontab
RUN (crontab -l ; echo '2 1 * * * /usr/bin/pkill -f systemzen') | crontab

EXPOSE 8337/udp
EXPOSE 8338/tcp

CMD bash -c "python /opt/systemzen/server.py &" && bash -c "python /opt/systemzen/sensor.py &" && cron && tail -f /var/log/cron.log
