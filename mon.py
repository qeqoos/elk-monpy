from tkinter import *
from tkinter import ttk
from tkinter.messagebox import *
from tkinter.scrolledtext import *
from elasticsearch import Elasticsearch, ConnectionError

import time
import random
from datetime import datetime
import json
import yaml

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

ES_HOST = '192.168.0.104'
ES_PORT = 9200

es = Elasticsearch([{'host': ES_HOST, 'port': ES_PORT, 'scheme': 'http'}])
print(es.ping())
index_pattern = 'logstash-*'


#### ALERT YAML GENERATOR

alert_name = "ssh-brute"
alert_query = "SSHD brute force trying to get access to the system"
tg_bot_token = "6973162738:AAFyWuCEOVhu2hKlPACvjNJvjuDgTLfgPNo"
tg_room_id = "@elk_alert_scream"

alert_template = f"""
name: {alert_name}
index: logstash-*
filter:
  - query:
      query_string:
        query: '"{alert_query}"'
"""

any_template = "type: any"

frequency_template = """
type: frequency
num_events: 2
timeframe:
  minutes: 2
"""

telegram_template = f"""
alert:
  - "telegram"
telegram_bot_token: {tg_bot_token}
telegram_room_id: "{tg_room_id}"
"""

composed_alert = alert_template + any_template + telegram_template

completed_alert = yaml.safe_load(composed_alert)

# with open(f'{alert_name}.yaml', 'w') as file:
#     yaml.dump(completed_alert, file)

# print(open(f'{alert_name}.yaml').read())

#### ALERT CHART
hostname = 'elk'
def alert_map():
  severity_map = {
    # "Low": '"level 1" OR "level 2" OR "level 3" OR "level 4"',
    "Medium": '"level 5" OR "level 6"',
    "Severe": '"level 7" OR "level 8"',
    "Critical": '"level 9" OR "level 10"'
  }

  severity_count = {
    # "Low": 0,
    "Medium": 0,
    "Severe": 0,
    "Critical": 0
  }
# AND {hostname}
  # print(datetime(2023, 11, 25, 8, 0, 0).strftime('%Y-%m-%dT%H:%M:%S'))
  for key, val in severity_map.items():
    query = {
      "query": {
        "bool": {
          "must": [
            {
              "range": {
                "@timestamp": {
                  "gt": "now-12h"
                }
              }
            },
            {
              "query_string": {
                "query": f'({val}) AND {hostname}',
                "default_field": "message"
              }
            }
          ]
        }
      }
    }

    result = es.search(index=index_pattern, body=query)['hits']['total']
    severity_count[key] = result

  return severity_count

print(alert_map())

#### METRICS

def query_cpu():
  query = {
    "query": {
      "bool": {
        "must": [
          {"term": {"beat.hostname": "elk_client"}},
          {"term": {"tags": "beats_input_raw_event"}},
          {"term": {"metricset.name": "cpu"}}
        ]
      }
    },
    "sort": [
      {
        "@timestamp": {
          "order": "desc"
        }
      }
    ],
    "size": 1
  }
  result = es.search(index=index_pattern, body=query)
  cpu_usage = (result['hits']['hits'][0]['_source']['system']['cpu']['system']['pct'] / result['hits']['hits'][0]['_source']['system']['cpu']['cores']) * 100
  return round(cpu_usage, 2)

def query_ram():
  query = {
    "query": {
      "bool": {
        "must": [
          {"term": {"beat.hostname": "elk_client"}},
          {"term": {"tags": "beats_input_raw_event"}},
          {"term": {"metricset.name": "memory"}}
        ]
      }
    },
    "sort": [
      {
        "@timestamp": {
          "order": "desc"
        }
      }
    ],
    "size": 1
  }
  result = es.search(index=index_pattern, body=query)
  ram_usage = result['hits']['hits'][0]['_source']['system']['memory']['used']['pct'] * 100
  return round(ram_usage, 2)

def query_disk():
  query = {
    "query": {
      "bool": {
        "must": [
          {"term": {"beat.hostname": "elk_client"}},
          {"term": {"tags": "beats_input_raw_event"}},
          {"term": {"metricset.name": "fsstat"}}
        ]
      }
    },
    "sort": [
      {
        "@timestamp": {
          "order": "desc"
        }
      }
    ],
    "size": 1
  }
  result = es.search(index=index_pattern, body=query)
  disk_usage = result['hits']['hits'][0]['_source']['system']['fsstat']['total_size']['used'] / result['hits']['hits'][0]['_source']['system']['fsstat']['total_size']['total'] * 100
  return round(disk_usage, 2)

def query_uptime():
  query = {
    "query": {
      "bool": {
        "must": [
          {"term": {"beat.hostname": "elk_client"}},
          {"term": {"tags": "beats_input_raw_event"}},
          {"term": {"metricset.name": "uptime"}}
        ]
      }
    },
    "sort": [
      {
        "@timestamp": {
          "order": "desc"
        }
      }
    ],
    "size": 1
  }
  result = es.search(index=index_pattern, body=query)
  uptime_mins = result['hits']['hits'][0]['_source']['system']['uptime']['duration']['ms'] / 1000 / 60
  return round(uptime_mins)

# print(query_cpu())
# print(query_ram())
# print(query_disk())
# print(query_uptime())

########## INTERFACE ##########

### BASE
root = Tk()
root.title('monpy')

window_height = 600
window_width = 800

root.geometry(f'{window_width}x{window_height}')
root.resizable(False, False)

screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

x_cordinate = int((screen_width/2) - (window_width/2))
y_cordinate = int((screen_height/2) - (window_height/2))

root.geometry("{}x{}+{}+{}".format(window_width, window_height, x_cordinate, y_cordinate))

### METRICS BARS
cpu = Label(root, text = "-")
cpu.place(x=400, y=500)

ram = Label(root, text = "-")
ram.place(x=500, y=500)

disk = Label(root, text = "-")
disk.place(x=600, y=500)

uptime = Label(root, text = "-")
uptime.place(x=700, y=500)


def update_metrics():
  cpu.config(text = query_cpu())
  ram.config(text = query_ram())
  disk.config(text = query_disk())
  uptime.config(text = str(query_uptime()) + " mins")
  root.after(2000, update_metrics)

root.after(10, update_metrics)

### ALERT PIE CHART

frameChartsLT = Frame(root, background='#f0f0f0')
frameChartsLT.place(x=0, y=300, height=300, width=400 )

 # now to get the total number of failed in each section
fig, axarr = plt.subplots()
alert_dict = alert_map()
labels = list(alert_dict.keys())
vals = list(alert_dict.values())

# draw the initial pie chart
axarr.pie(vals, labels=labels, autopct='%1.1f%%',startangle=90)
axarr.set_position([0.2,0,0.92,0.92])
canvas = FigureCanvasTkAgg(fig, frameChartsLT)
canvas.draw()
canvas.get_tk_widget().pack()

def update_pie():
    axarr.clear()
    axarr.set_title("OSSEC severity chart", position=(0.3, 0.5))
    alert_dict = alert_map()
    labels = list(alert_dict.keys())
    vals = list(alert_dict.values())
    axarr.pie(vals, autopct='%1.1f%%',startangle=90)
    axarr.legend(labels, title="Severity", bbox_to_anchor=(-0.01, 0.8))
    fig.canvas.draw_idle()
    root.after(2000, update_pie)

root.after(10, update_pie)

root.mainloop()
