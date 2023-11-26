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

index_pattern = 'logstash-*'
ES_HOST = ''
ES_PORT = 9200
es = ''

#### ALERT YAML GENERATOR
template_type = ""
notification_type = "telegram"

def compose_alert():
  alert_name = "ssh-brute"
  alert_query = "SSHD brute force trying to get access to the system"
  num_events = ""
  timeframe = ""
  tg_bot_token = "6973162738:AAFyWuCEOVhu2hKlPACvjNJvjuDgTLfgPNo"
  tg_room_id = "@elk_alert_scream"
  email_address = "pavel.patalashko@gmail.com"

  alert_template = f"""
  name: {alert_name}
  index: {index_pattern}
  filter:
    - query:
        query_string:
          query: '"{alert_query}"'
  """

  if template_type == "any":
    type_template = "type: any"
  elif template_type == "frequency":
    num_events = num_events_entry.get()
    timeframe = frequency_time_entry.get()
    type_template = f"""
  type: frequency
  num_events: {num_events}
  timeframe:
    minutes: {timeframe}
    """

  if notification_type == "telegram":
    notification_template = f"""
  alert:
    - "telegram"
  telegram_bot_token: {tg_bot_token}
  telegram_room_id: "{tg_room_id}"
    """
  elif notification_type == "email":
    notification_template = f"""
  alert:
  - "email"
  email:
    - "{email_address}"
  smtp_host: "smtp.gmail.com"
  smtp_port: 587
  smtp_ssl: true
  smtp_auth_file: "/root/gmail_auth_file"
    """

  composed_alert = alert_template + type_template + notification_template
  print(composed_alert)

  completed_alert = yaml.safe_load(composed_alert)

  # with open(f'{alert_name}.yaml', 'w') as file:
  #     yaml.dump(completed_alert, file)

  # print(open(f'{alert_name}.yaml').read())

#### ALERT CHART

def alert_map(hostname, used_time):
  severity_map = {
    "Low": '"level 3" OR "level 4"',
    "Medium": '"level 5" OR "level 6"',
    "Severe": '"level 7" OR "level 8"',
    "Critical": '"level 9" OR "level 10"'
  }

  severity_count = {
    "Low": 0,
    "Medium": 0,
    "Severe": 0,
    "Critical": 0
  }

  for key, val in severity_map.items():
    query = {
      "query": {
        "bool": {
          "must": [
            {
              "range": {
                "@timestamp": {
                  "gt": f"now-{used_time}"
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

#### METRICS

def query_cpu(hostname):
  query = {
    "query": {
      "bool": {
        "must": [
          {"term": {"beat.hostname": f"{hostname}"}},
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
  cpu_usage = (result['hits']['hits'][0]['_source']['system']['cpu']['total']['pct'] / result['hits']['hits'][0]['_source']['system']['cpu']['cores']) * 100
  return round(cpu_usage, 2)

def query_ram(hostname):
  query = {
    "query": {
      "bool": {
        "must": [
          {"term": {"beat.hostname": f"{hostname}"}},
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
  ram_allocated = result['hits']['hits'][0]['_source']['system']['memory']['used']['bytes'] / 1024**3
  ram_total = result['hits']['hits'][0]['_source']['system']['memory']['total'] / 1024**3
  return [round(ram_usage, 2), round(ram_allocated, 1), round(ram_total, 1)]

def query_disk(hostname):
  query = {
    "query": {
      "bool": {
        "must": [
          {"term": {"beat.hostname": f"{hostname}"}},
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
  disk_allocated = result['hits']['hits'][0]['_source']['system']['fsstat']['total_size']['used'] / 1024**3
  disk_total = result['hits']['hits'][0]['_source']['system']['fsstat']['total_size']['total'] / 1024**3
  return [round(disk_usage, 2), round(disk_allocated, 1), round(disk_total, 1)]

def query_uptime(hostname):
  query = {
    "query": {
      "bool": {
        "must": [
          {"term": {"beat.hostname": f"{hostname}"}},
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
  uptime_mins = result['hits']['hits'][0]['_source']['system']['uptime']['duration']['ms'] / 1000
  return round(uptime_mins)

########## INTERFACE ##########

### BASE
root = Tk()
root.title('monpy')

window_height = 600
window_width = 800

root.resizable(False, False)

screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

x_cordinate = int((screen_width/2) - (window_width/2))
y_cordinate = int((screen_height/2) - (window_height/2))

root.geometry("{}x{}+{}+{}".format(window_width, window_height, x_cordinate, y_cordinate))


def create_lines(canvas):
    canvas.create_line(0, window_height/2 - 10, window_width, window_height/2 - 10, fill="black") # horiz
    canvas.create_line(window_width/2, 0, window_width/2, window_height, fill="black") # vertic

canvas_bg = Canvas(root, width=window_width, height=window_height, background='white')
canvas_bg.pack()
create_lines(canvas_bg)

### ALERT COMPOSER
alert_composer_label = Label(root, text='Alert composer', font='DejaVu 14', background='white').place(x=540, y=10)

query_label = Label(root, text='Query:', background='white').place(x=413, y=47)
query_entry = Entry(root, width=53, borderwidth=3)
query_entry.place(x=460, y=47)
### TYPE FRAME
alert_type_frame = LabelFrame(root, text="Type", background='white', highlightbackground="#f0f0f0", highlightcolor="#f0f0f0")
alert_type_frame.place(x=410, y=75)
def any_choice():
    global template_type
    frequency_time_entry.configure(state='disabled')
    num_events_entry.configure(state='disabled')

    frequency_time_entry.update()
    num_events_entry.update()
    template_type = "any"

def frequency_choice():
    global template_type
    frequency_time_entry.configure(state='normal')
    num_events_entry.configure(state='normal')

    frequency_time_entry.update()
    num_events_entry.update()
    template_type = "frequency"

var = StringVar()
rb_any = Radiobutton(alert_type_frame, text='Any', variable=var, value='0', background="white", command=any_choice).grid(row=0, column=0, padx=0, pady=0, sticky=W)
rb_frequency = Radiobutton(alert_type_frame, text='Frequency', variable=var, value='1', background="white", command=frequency_choice).grid(row=0, column=1, padx=0, pady=0, sticky=W)

frequency_time_label = Label(alert_type_frame, text='Timeframe:', background='white')
frequency_time_label.grid(row=1, column=1, padx=20, pady=0, sticky=W)

frequency_time_entry = Entry(alert_type_frame, width=5, borderwidth=3)
frequency_time_entry.grid(row=1, column=2, padx=3, pady=0, sticky=E)

num_events_label = Label(alert_type_frame, text='Events number:', background='white')
num_events_label.grid(row=2, column=1, padx=20, pady=0, sticky=W)

num_events_entry = Entry(alert_type_frame, width=5, borderwidth=3)
num_events_entry.grid(row=2, column=2, padx=3, pady=0, sticky=E)

### NOTIFICATION
notification_type_frame = LabelFrame(root, text="Notification", background='white', highlightbackground="#f0f0f0", highlightcolor="#f0f0f0")
notification_type_frame.place(x=410, y=170)
def telegram_choice():
    global notification_type
    bot_token_entry.configure(state='normal')
    channel_id_entry.configure(state='normal')
    email_entry.configure(state='disabled')

    bot_token_entry.update()
    channel_id_entry.update()
    email_entry.update()
    notification_type = "telegram"

def email_choice():
    global notification_type
    bot_token_entry.configure(state='disabled')
    channel_id_entry.configure(state='disabled')
    email_entry.configure(state='normal')

    bot_token_entry.update()
    channel_id_entry.update()
    email_entry.update()
    notification_type = "email"

var2 = StringVar()
rb_telegram = Radiobutton(notification_type_frame, text='Telegram', variable=var2, value='0', background="white", command=telegram_choice).grid(row=0, column=0, padx=0, pady=0, sticky=W)
rb_email = Radiobutton(notification_type_frame, text='Email', variable=var2, value='1', background="white", command=email_choice).grid(row=0, column=2, padx=20, pady=0, sticky=W)

bot_token_label = Label(notification_type_frame, text='Bot token:', background='white')
bot_token_label.grid(row=1, column=0, padx=5, pady=0, sticky=W)

bot_token_entry = Entry(notification_type_frame, width=17, borderwidth=3)
bot_token_entry.grid(row=1, column=1, padx=0, pady=0, sticky=E)

channel_id_label = Label(notification_type_frame, text='Channel ID:', background='white')
channel_id_label.grid(row=2, column=0, padx=5, pady=0, sticky=W)

channel_id_entry = Entry(notification_type_frame, width=17, borderwidth=3)
channel_id_entry.grid(row=2, column=1, padx=0, pady=0, sticky=E)

email_label = Label(notification_type_frame, text='Email address:', background='white')
email_label.grid(row=1, column=2, padx=20, pady=0, sticky=W)

email_entry = Entry(notification_type_frame, width=23, borderwidth=3)
email_entry.grid(row=2, column=2, padx=20, pady=0, sticky=E)

Button(root, text='Compose alert', command=compose_alert, width=19, height=1).place(x=645, y=138)
### MAIN INFO BLOCK
settings_label = Label(root, text='Server settings', font='DejaVu 14', background='white').place(x=130, y=10)

# ELK server
server_frame = Frame(root, bd=2, relief=GROOVE, background='white', highlightbackground="#f0f0f0", highlightcolor="#f0f0f0")
server_frame.place(x=10, y=60)

elk_hostname_label = Label(server_frame, text='ELK server hostname:', background='white')
elk_hostname_label.grid(row=0, column=0, padx=0, pady=3, sticky=W)

elk_hostname_entry = Entry(server_frame, width=15, borderwidth=3)
elk_hostname_entry.grid(row=0, column=1, padx=3, pady=3, sticky=E)
elk_hostname_entry.insert(0, "elk")

elk_ip_label = Label(server_frame, text='ELK server IP:', background='white')
elk_ip_label.grid(row=1, column=0, padx=0, pady=3, sticky=W)

elk_ip_entry = Entry(server_frame, width=15, borderwidth=3)
elk_ip_entry.grid(row=1, column=1, padx=3, pady=3, sticky=E)
elk_ip_entry.insert(0, "192.168.0.104")

elk_readiness_status = Label(root, text='Status:', background='white').place(x=275, y=95)
elk_readiness_label = Label(root, text='down', background='white', foreground='red')
elk_readiness_label.place(x=330, y=95)

# ES_HOST = elk_ip_entry.get()
# es = Elasticsearch([{'host': ES_HOST, 'port': ES_PORT, 'scheme': 'http'}])

### Target
target_frame = Frame(root, bd=2, relief=GROOVE, background='white', highlightbackground="#f0f0f0", highlightcolor="#f0f0f0")
target_frame.place(x=10, y=150)

target_hostname_label = Label(target_frame, text='Target server hostname:', background='white')
target_hostname_label.grid(row=0, column=0, padx=0, pady=3, sticky=W)

target_hostname_entry = Entry(target_frame, width=15, borderwidth=3)
target_hostname_entry.grid(row=0, column=1, padx=3, pady=3, sticky=E)
target_hostname_entry.insert(0, "elk_client")

hostname = target_hostname_entry.get()

target_ip_label = Label(target_frame, text='Target server IP:', background='white')
target_ip_label.grid(row=1, column=0, padx=0, pady=3, sticky=W)

target_ip_entry = Entry(target_frame, width=15, borderwidth=3)
target_ip_entry.grid(row=1, column=1, padx=3, pady=3, sticky=E)
target_ip_entry.insert(0, "192.168.0.103")

target_readiness_status = Label(root, text='Status:', background='white').place(x=275, y=185)
target_readiness_label = Label(root, text='down', background='white',  foreground='red')
target_readiness_label.place(x=330, y=185)

### METRICS BARS
load_txt = Label(root, text = "Resource metrics", font='DejaVu 14', background='white').place(x=520, y=293)

cpu_txt = Label(root, text = "CPU", background='white').place(x=478, y=325)
cpu_pct = Label(root, text = "- %", background='white')
cpu_pct.place(x=478, y=550)
cpu_bar = ttk.Progressbar(root, orient='vertical', length=200, mode='determinate', style="TProgressbar")
cpu_bar.place(x=480, y=350)

ram_txt = Label(root, text = "RAM", background='white').place(x=575, y=325)
ram_pct = Label(root, text = "- %", background='white')
ram_pct.place(x=575, y=550)
ram_vals = Label(root, text = "- / -", background='white')
ram_vals.place(x=570, y=570)
ram_bar = ttk.Progressbar(root, orient='vertical', length=200, mode='determinate', style="TProgressbar")
ram_bar.place(x=580, y=350)

disk_txt = Label(root, text = "Disk", background='white').place(x=675, y=325)
disk_pct = Label(root, text = "- %", background='white')
disk_pct.place(x=675, y=550)
disk_vals = Label(root, text = "- / -", background='white')
disk_vals.place(x=670, y=570)
disk_bar = ttk.Progressbar(root, orient='vertical', length=200, mode='determinate', style="TProgressbar")
disk_bar.place(x=680, y=350)

def update_metrics():
  hostname = target_hostname_entry.get()
  try:
    cpu_parsed = query_cpu(hostname)
    ram_parsed = query_ram(hostname)
    disk_parsed = query_disk(hostname)
  except:
    cpu_parsed = 0
    ram_parsed = [0, "-", "-"]
    disk_parsed = [0, "-", "-"]

  cpu_pct.config(text = str(cpu_parsed) + ' %')
  cpu_bar['value'] = cpu_parsed

  ram_pct.config(text = str(ram_parsed[0]) + ' %')
  ram_vals.config(text = str(ram_parsed[1]) + '/' + str(ram_parsed[2]) + ' GB')
  ram_bar['value'] = ram_parsed[0]

  disk_pct.config(text = str(disk_parsed[0]) + ' %')
  disk_vals.config(text = str(disk_parsed[1]) + '/' + str(disk_parsed[2]) + ' GB')
  disk_bar['value'] = disk_parsed[0]

  root.after(4000, update_metrics)

### UPTIME
def seconds_to_hms(seconds):
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return "{:02}:{:02}:{:02}".format(int(hours), int(minutes), int(seconds))

uptime_sec = 0
uptime = Label(root, text = ("Uptime: -"), background='white')
uptime.place(x=450, y=570)

def update_uptime():
  global uptime_sec
  uptime_sec += 1
  uptime.config(text = str("Uptime: " + seconds_to_hms(uptime_sec)))
  root.after(1000, update_uptime)

### ALERT PIE CHART
def autopct_format(values):
    def my_format(pct):
        total = sum(values)
        val = int(round(pct*total/100.0))
        return '{:.1f}%\n({v:d})'.format(pct, v=val)
    return my_format

frameChartsLT = Frame(root)
frameChartsLT.place(x=0, y=300, height=300, width=400 )

timeframe_frame = Frame(root, bd=2, relief=GROOVE, background='white', highlightbackground="#f0f0f0", highlightcolor="#f0f0f0")
timeframe_frame.place(x=10, y=330)

# Create label and entry within the frame
timeframe_label = Label(timeframe_frame, text='Timeframe (e.g. 10m, 1h):', font='DejaVu 10', background='white')
timeframe_label.grid(row=0, column=0, padx=0, pady=0, sticky=W)

timeframe = Entry(timeframe_frame, width=10, borderwidth=3)
timeframe.grid(row=1, column=0, padx=3, pady=0, sticky=W)
timeframe.insert(0, "24h")
used_time = timeframe.get()
# print(alert_map(hostname, used_time))

 # now to get the total number of failed in each section
fig, axarr = plt.subplots()
clour_map = {
  "Low": "#f0f0f0",
  "Medium": "yellow",
  "Severe": "orange",
  "Critical": "red"
}

# alert_dict = {key: value for key, value in alert_map(hostname, used_time).items() if value != 0}
# labels = list(alert_dict.keys())
vals = [0,1]
color_list = ["#f0f0f0"]
# draw the initial pie chart
axarr.set_title("OSSEC severity chart", position=(0.3, 0.5))
axarr.pie(vals, autopct=autopct_format(vals), startangle=90, colors=color_list)
axarr.set_position([0.2,0,0.92,0.92])
canvas = FigureCanvasTkAgg(fig, frameChartsLT)
canvas.draw()
canvas.get_tk_widget().pack()

def update_pie():
    axarr.clear()
    axarr.set_title("OSSEC severity chart", position=(0.3, 0.5))
    hostname = target_hostname_entry.get()
    used_time = timeframe.get()
    alert_dict = {key: value for key, value in alert_map(hostname, used_time).items() if value != 0}
    labels = list(alert_dict.keys())
    vals = list(alert_dict.values())
    color_list = [clour_map[value] for value in labels]
    axarr.pie(vals, autopct=autopct_format(vals), startangle=90, colors=color_list)
    axarr.legend(labels, title="Severity", bbox_to_anchor=(-0.01, 0.8))
    fig.canvas.draw_idle()
    root.after(5000, update_pie)

root.configure(background="white")

def check_elk_host():
  ES_HOST = elk_ip_entry.get()
  es = Elasticsearch([{'host': ES_HOST, 'port': ES_PORT, 'scheme': 'http'}])
  if es.ping():
    print("Host up.")
    elk_readiness_label.configure(text="Running", foreground="green")
    return True
  else:
    target_readiness_label.configure(text="Down", foreground="red")
    print("Waiting for host to become online...")
    return False

def check_client():
   target_hostname = target_hostname_entry.get()
   target_ip = target_ip_entry.get()
   if target_hostname in ['elk', 'elk_client', 'elk_client2'] and target_ip in ['192.168.0.103', '192.168.0.104', '192.168.0.105']:
      target_readiness_label.configure(text="Running", foreground="green")
      return True
   else:
      target_readiness_label.configure(text="Down", foreground="red")

def start_mon():
   global ES_HOST, es, uptime_sec
   ES_HOST = elk_ip_entry.get()
   es = Elasticsearch([{'host': ES_HOST, 'port': ES_PORT, 'scheme': 'http'}])
   if check_elk_host() and check_client():
      uptime_sec = query_uptime(hostname)
      root.after(10, update_pie)
      root.after(10, update_uptime)
      root.after(10, update_metrics)

Button(root, text='Check ELK server', command=check_elk_host, width=14, height=1).place(x=275, y=60)
Button(root, text='Check client', command=check_client, width=14, height=1).place(x=275, y=150)
Button(root, text='Start monitoring', command=start_mon, width=14, height=1).place(x=150, y=240)

root.mainloop()
