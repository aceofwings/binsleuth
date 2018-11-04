#!/usr/bin/env python

import os
import psutil
import json
from datetime import datetime
from report import Report
  
class ProcSleuth:

  def __init__(self, exe=None):
    self._connection_memory = {}
    self._process_memory = {} 
    self._go = True
    self._exe = exe
    self._cmdline = None
    self._create_time = None
    self._context_switch = None
    self._cpu_times = None
    self._lock_proc = None
    self._proc_cons = []
    self._proc_children = []
    self._proc_mem_map = []
    self._proc_con_memory = {}
    self._file_io = []
    self._file_memory = {}
    self._proc_children_memory = {}
    
    self.SIZE = 300 
    # json data forms
    self._file_report =[]
    self._con_report = []
    self._child_report = []
    
  
  def set_state(self):
  
    ''' Set the current state of process list 
    
      this function applies to a list of processes
      representing the current state of all processes
    '''
    
    process_list = []
    for temp_process in psutil.process_iter():
      try:
        process_list.append(temp_process)
        self._process_memory[process_id] = temp_process.name()
        self._connection_memory[temp_process.name()] = temp_process.connections()
      except Exception as err:
        pass
    return process_list
  
  def _set_proc_state(self):
  
    ''' Set the current state of process 
    
      this function applies to a process' state,
      not the state of the process list
      this functions gets called in run()
    '''
    
    assert self._lock_proc, "No process locked"
    
    self._proc_cons.extend(self._lock_proc.connections())
    self._proc_children.extend(self._lock_proc.children(recursive=True))
    try: self._proc_mem_map.extend(self._lock_proc.mem_maps())
    except: pass
    
  def monitor_processes(self, previous_process_list):
    
    ''' Print changes to process list to stdout 
      this method essentially listens for the process given to ProcSleuth
      when initialized
      when that process is found this function will stop looping and 
      _monitor() will begin to monitor the locked processes state
      
      you may think, well why do you need to keep track of past states?
      why not just grab the process list and see if its there?
      well thats a great question. Unfortunately, when I tried that it did not
      work. Maybe youl will have better luck
      
      
      @TODO fuzzy find process so exact name does not need to be known
      
      :previous_process_list: an array of Process objects 
    '''
    
    current_process_list = self.set_state()
    matched = 0
    
    for proc_current in current_process_list:
      for proc_previous in previous_process_list:
        if proc_previous == proc_current:
          matched = 1
          break
      if not matched:
        name = str(proc_current.name()).lower()
        print(' +++ ' + name + ' : ' + str(proc_current.pid))
        if proc_current.connections():
          print(proc_current.connections())
          
        if name == self._exe:
          print('\nHooked Process\n')
          self._cmdline = proc_current.cmdline()
          self._create_time = proc_current.create_time()
          for c in proc_current.connections():
            self._proc_con_memory[c] = {"start time": str(datetime.fromtimestamp(proc_current.create_time()))}
          self._lock_proc = proc_current
          self._go = False
        
      matched = 0
    matched = 0
    
    for proc_previous in previous_process_list:
      try:
        name = str(proc_previous.name()).lower()
      except Exception as err:
        try:
          name = str(self._process_memory[proc_previous.pid])
        except Exception as err:
          name = proc_previous
      for proc_current in current_process_list:
        if proc_previous == proc_current:
          matched = 1
          break
      if not matched:
        print(' --- ' + str(name) + ' : ' + str(proc_previous.pid))
      matched = 0

    return current_process_list
 
 
  def _monitor(self):
    
    ''' monitor the target process
      call individual monitoring functions
    '''
    
    assert self._lock_proc, "No process locked"
    
    self._go = True
    
    while self._go:
      
      self._monitor_network_cons()
      self._monitor_file_io()
      self._monitor_children()
      
    return 

    
  def process_exits(self):
    
    ''' checks if the process is still running 
      return boolean
    '''
    
    if psutil.pid_exists(self._lock_proc.pid):
      try:
        if self._lock_proc.name() == psutil.Process(self._lock_proc.pid).name() and psutil.Process(self._lock_proc.pid).status() == 'running':
          self._context_switch = self._lock_proc.num_ctx_switches()
          self._cpu_times = self._lock_proc.cpu_times()
          return True
      except: pass
      
    for proc in psutil.process_iter():
      try:
        if self._lock_proc.name().lower() == proc.name().lower():
          self._lock_proc = psutil.Process(proc.pid)
          self._context_switch = self._lock_proc.num_ctx_switches()
          self._cpu_times = self._lock_proc.cpu_times()
          return True
      except: return False
    return False
  
  
  def _terminate(self):
    
    ''' terminate all children on recursive child list
      send kill sig if terminate fails
    '''
    
    if self._proc_children:
      for child in self._proc_children[-1]:
        try: child.terminate()
        except: pass
      dead, alive = psutil.wait_procs(self._proc_children[-1], timeout=3)
      for kiddie in alive:
        try: kiddie.kill()
        except: pass
   
  def _monitor_file_io(self):
    
    ''' monitor file i/o operations performed by locked process
    '''
    
    matched = 0
    
    # term if proc is kill
    if not self.process_exits():
      self._terminate()
      self._go = False
      return
      
    # get files opened by the locked process
    # if an error is thrown it is because the process is dead
    # so we exit
    try: cur_files = psutil.Process(self._lock_proc.pid).open_files()
    except:
      self._go = False
      return
    
    # if its in my current state and not in my past, its new
    for new_file in cur_files:
      for old_file in self._file_io:
        if new_file == old_file:
          matched = 1
          break
      
      if not matched:
        timestamp = datetime.now()
        # map file obj -> {}
        self._file_memory[new_file] = {"start time": timestamp, "end time": "???"}
      
      matched = 0
    matched = 0
    
    # if its is my past by not in my current, it ended
    for old_file in self._file_io:
      for new_file in cur_files:
        if old_file == new_file:
          matched = 1
          break
          
      if not matched:
        timestamp = datetime.now()
        try: self._file_memory[old_file]["end time"] = timestamp
        except:
          self._file_memory[old_file]["end time"] = {"start time": "???", "end time": timestamp}
      matched = 0
      
    # set my past state to my current state
    # to prepare for the next call
    self._file_io = cur_files


  def _monitor_network_cons(self):
    
    
    ''' monitor network connections being made by the locked
      process
      see _monitor_file_io for more comments
    '''
    
    matched = 0

    if not self.process_exits():
      self._terminate()
      self._go = False
      return
      
    try: cur_cons = psutil.Process(self._lock_proc.pid).connections()
    except:
      self._go = False
      return
    for new_con in cur_cons:
      for old_con in self._proc_cons:
        if new_con == old_con:
          matched = 1
          break
          
      if not matched:
        timestamp = datetime.now()
        self._proc_con_memory[new_con] = {"start time": timestamp, "end time": "???"}
      matched = 0
    matched = 0
    
    for old_con in self._proc_cons:
      for new_con in cur_cons:
        if old_con == new_con:
          matched = 1
          break
          
      if not matched:
        timestamp = datetime.now()
        try: self._proc_con_memory[old_con]["end time"] = timestamp
        except: self._proc_con_memory[old_con] = {"start time": "???", "end time": timestamp}
      matched = 0
    
    self._proc_cons = cur_cons
 
 
  def _monitor_children(self):
    
  
    ''' monitor child processes being spawned by the locked
      process
      see _monitor_file_io for more comments
    '''
 
    assert self._lock_proc, "No process locked"
 
    if not self.process_exits():
      self._terminate()
      self._go = False
      return
      
    try: child_state = [proc for proc in psutil.Process(self._lock_proc.pid).children(recursive=True)]
    except:
      self._go = False
      return
    
    matched = 0
    
    for new_child in child_state:
      for old_child in self._proc_children:
        if new_child == old_child:
          matched = 1
          break
        
      if not matched:
        timestamp = datetime.now()
        # a custom object is created so we dont need to handle the termination propagating to all past states of a process
        # (we wont be able to read this data after we send a term sig to the process)
        self._proc_children_memory[new_child] = {"start time": timestamp, "end time": "???", "exe": new_child.exe(), "open files": new_child.open_files(), "net cons": new_child.connections()}
      matched = 0
    matched = 0
    
    for old_child in self._proc_children:
      for new_child in child_state:
        if new_child == old_child:
          matched = 1
          break
        
      if not matched:
        timestamp = datetime.now()
        try: self._proc_children_memory[old_child]["end time"] = timestamp
        except: self._proc_children_memory[old_child] = {"start time": "???", "end time": timestamp}
      matched = 0
    
    self._proc_children = child_state
    
    
  def _d3js_child(self):
 
    ''' a function to normalize the process' child process
      information for use by d3js and returning general json for user
      
    '''

    final_child = []

    for k,v in self._proc_children_memory.items():
      final_child.append(
        {
          "name": "Child process",
          "children": [
            {
              "name": "EXE: " + str(v["exe"]),
              "self.SIZE": self.SIZE
            },
            {
              "name": "Time info",
              "children": [
                {
                  "name": "Start time: " + str(v["start time"]),
                  "self.SIZE": self.SIZE
                },
                {
                  "name": "End time: " + str(v["end time"]),
                  "self.SIZE": self.SIZE
                }
              ]
            },
            {
              "name": "Connections",
              "children": [
                {
                  "name": "Connection",
                  "children": [
                    {
                      "name": "Status: " + str(con.status),
                      "self.SIZE": self.SIZE
                    },
                    {
                      "name": "File descriptor: " + str(con.fd),
                      "self.SIZE": self.SIZE
                    },
                    {
                      "name": "Socket type: " + str(con.type),
                      "self.SIZE": self.SIZE
                    },
                    {
                      "name": "Family: " + "IPv4" if con.family == 2 else "IPv6" if con.family == 12 else str(con.family),
                      "self.SIZE": self.SIZE
                    },
                    {
                      "name": "Local host",
                      "children": [
                        {
                          "name": "Address: " + str(con.laddr.ip),
                          "self.SIZE": self.SIZE
                        },
                        {
                          "name": "Port: " + str(con.laddr.port),
                          "self.SIZE": self.SIZE
                        }
                      ]
                    },
                    {
                      "name": "Remote host",
                      "children": [
                        {
                          "name": "Address: " + (str(con.raddr.ip) if con.raddr else "???"),
                          "self.SIZE": self.SIZE
                        },
                        {
                          "name": "Port: " + (str(con.laddr.port) if con.raddr else "???"),
                          "self.SIZE": self.SIZE
                        }
                      ]
                    }
                  ]
                } for con in v["net cons"]
              ]
            },
            {
              "name": "File Operations",
              "children": [
                {
                  "name": "File operation  ..." + str(file.path[:len(file.path)//2]),
                  "children": [
                    {
                      "name": "path: " + str(file.path),
                      "self.SIZE": self.SIZE
                    },
                    {
                      "name": "File offset: " + str(file.position),
                      "self.SIZE": self.SIZE
                    },
                    {
                      "name": "Meta data",
                      "children": [
                        {
                          "name": "Mode: " + str(file.mode),
                          "self.SIZE": self.SIZE
                        },
                        {
                          "name": "File descriptor: " + str(file.fd),
                          "self.SIZE": self.SIZE
                        },
                        {
                          "name": "Offset: " + str(file.position),
                          "self.SIZE": self.SIZE
                        },
                        {
                          "name": "Flags: " + str(file.flags),
                          "self.SIZE": self.SIZE
                        }
                      ]
                    } 
                  ]
                } for file in v["open files"]
              ]
            }
          ]
        }
      )
    
    self._child_report = final_child
  
  def _d3js_file(self):
      
    ''' a function to normalize the process' file operations
      information for use by d3js and returning general json for user
      
    a few different representations were explored here
    @TODO pick the best representation for plain json
    
    '''
  
    final_file = []
    
    mode_file_map = {}
    # mode_file_map = map of file open mode -> file object
    for file_obj in self._file_memory:
    
      try: mode_file_map[str(file_obj.mode)].append(file_obj)
      except:
        mode_file_map[str(file_obj.mode)] = []
        mode_file_map[str(file_obj.mode)].append(file_obj)

    
    root_file_map = {}
    # root_file_map = map of root directory -> file object
    for k, v in mode_file_map.items():
      root_file_map[k] = {}
      
      for file in v:
        dir = file.path.split('/')[1]
        
        try: root_file_map[k][dir].append(file)
        except:
          root_file_map[k][dir] = []
          root_file_map[k][dir].append(file)
        
    for k, v in root_file_map.items():
      # k is mode
      # v is root dir -> [file object, file obj..]
      root = []
      for val in v:
        # val is /etc, /usr etc
        file_io = []
        for file in v[val]:
      
          start = self._file_memory[file]["start time"]
          end = self._file_memory[file]["end time"]
          
          file_io.append(
            {
              "name": "File operation  ..." + str(file.path[:len(file.path)//2]) + "...     Duration: " + (str(end - start) if not isinstance(start, str) and not isinstance(end, str) else "???"),
              "children": [
                {
                  "name": "path: " + str(file.path),
                  "self.SIZE": self.SIZE
                },
                {
                  "name": "File offset: " + str(file.position),
                  "self.SIZE": self.SIZE
                },
                {
                  "name": "Time info",
                  "children": [
                    {
                      "name": "Access time: " + str(start),
                      "self.SIZE": self.SIZE
                    },
                    {
                      "name": "Close time: " + str(end),
                      "self.SIZE": self.SIZE
                    },
                    {
                      "name": "Duration: " + (str(end - start) if not isinstance(start, str) and not isinstance(end, str) else "???"),
                      "self.SIZE": self.SIZE
                    }
                  ]
                }
              ]
            }
          )
      
        root.append(
          {
            "name": "Root directory: /" + str(val) + "    Operation Count: " + str(len(v[val])),
            "children": file_io
          }        
        )
      
      final_file.append(
        {
          "name": "Mode: " + str(k),
          "children": root
        }
      )
      
    self._file_report = final_file
      
      
  def _d3js_con(self):
    
    ''' a function to normalize the process' network connection
      information for use by d3js and returning general json for user
      
    a few different representations were explored here
    @TODO pick the best representation for plain json
    
    '''
    
    final_con = []
    
    family_con_map = {}
    # map family -> connections
    for k, v in self._proc_con_memory.items():
      
      try: family_con_map[k.family].append(k)
      except:
        family_con_map[k.family] = []
        family_con_map[k.family].append(k)
    
    
    socket_con_map = {}
    # map socket -> connections
    for k, v in family_con_map.items():
      socket_con_map[k] = {}
      
      for con in v:
        try: socket_con_map[k][str(con.laddr.ip) + ':' + str(con.laddr.port)].append(con)
        except:
          socket_con_map[k][str(con.laddr.ip) + ':' + str(con.laddr.port)] = []
          socket_con_map[k][str(con.laddr.ip) + ':' + str(con.laddr.port)].append(con)    
    
    for k, v in socket_con_map.items():
      # k is socket
      # v is [con]
      
      outer_con = []
      for val in v:
        # val is con
        con_items = []
        for con in v[val]:
        
          start = self._proc_con_memory[con]["start time"]
          end = self._proc_con_memory[con]["end time"]
          
          con_items.append(
            {
              "name": "Connection    Duration: " + (str(end - start) if not isinstance(start, str) and not isinstance(end, str) else "???"),
              "children": [
                {
                  "name": "Status: " + str(con.status),
                  "self.SIZE": self.SIZE
                },
                {
                  "name": "File descriptor: " + str(con.fd),
                  "self.SIZE": self.SIZE
                },
                {
                  "name": "Socket type: " + str(con.type),
                  "self.SIZE": self.SIZE
                },
                {
                  "name": "Local host",
                  "children": [
                    {
                      "name": "Address: " + str(con.laddr.ip),
                      "self.SIZE": self.SIZE
                    },
                    {
                      "name": "Port: " + str(con.laddr.port),
                      "self.SIZE": self.SIZE
                    }
                  ]
                },
                {
                  "name": "Remote host",
                  "children": [
                    {
                      "name": "Address: " + (str(con.raddr.ip) if con.raddr else "???"),
                      "self.SIZE": self.SIZE
                    },
                    {
                      "name": "Port: " + (str(con.laddr.port) if con.raddr else "???"),
                      "self.SIZE": self.SIZE
                    }
                  ]
                },
                {
                  "name": "Time info",
                  "children": [
                    {
                      "name": "Start time: " + str(start),
                      "self.SIZE": self.SIZE
                    },
                    {
                      "name": "End time: " + str(end),
                      "self.SIZE": self.SIZE
                    }
                  ]
                }
              ]
            }
          )
      
        outer_con.append(
          {
            "name": "Socket: " + str(val) + "    Connection Count: " + str(len(v[val])),
            "children": con_items
          }
        )
    
      final_con.append(
        {
          "name": "Family: " + "IPv4" if k == 2 else "IPv6" if k == 12 else str(k),
          "children": outer_con
        }
      )

    self._con_report = final_con
    
    

  def _d3js_data_hub(self):
     
    ''' this function pieces together a dynamic report into one html file
      the relationships are all very simple parent -> child relationships
      allowing us flexability 
      
      the Report handles the creation of the semi-self-contained html
      file
      
      @TODO we can pull d3js package into the enviroment making it a fully
        self-contained html file
        currently it reaches out to the d3js server for libraries
    
    '''
     
    self._d3js_file()
    self._d3js_con()
    self._d3js_child()
     
    report = {
      "name": "Report",
      "children": [
        {
          "name": "Dynamic Operations",
          "children": [
            {
              "name": "EXE: " + str(self._exe)
            },
            {
              "name": "Command line args",
              "children": [
                {
                  "name": str(cmd),
                  "self.SIZE": self.SIZE
                } for cmd in self._cmdline
              ]
            },
            {
              "name": "Create time: " +  str(datetime.fromtimestamp(self._create_time)),
              "self.SIZE": self.SIZE
            },
            {
              "name": "Context switch counts",
              "children": [
                {
                  "name": "Voluntary: " + str(self._context_switch.voluntary),
                  "self.SIZE": self.SIZE
                },
                {
                  "name": "Involuntary: " + str(self._context_switch.involuntary),
                  "self.SIZE": self.SIZE
                }
              ]
            },
            {
              "name": "CPU times",
              "children": [
                {
                  "name": "User: " + str(self._cpu_times.user) + " seconds",
                  "self.SIZE": self.SIZE
                },
                {
                  "name": "System: " + str(self._cpu_times.system) + " seconds",
                  "self.SIZE": self.SIZE
                },
                {
                  "name": "Children system: " + str(self._cpu_times.children_system) + " seconds",
                  "self.SIZE": self.SIZE
                },
                {
                  "name": "Children user: " + str(self._cpu_times.children_user) + " seconds",
                  "self.SIZE": self.SIZE
                }
              ]
            },
            {
              "name": "File Operations",
              "children": self._file_report
            },
            {
              "name": "Network Connections",
              "children": self._con_report
            },
            {
              "name": "Child Processes",
              "children": self._child_report
            }
          ]
        }
      ]
    }
 
    d3 = Report(report, build_d3js=True)
    
  
  def run(self):
    
    ''' waits for process to be hooked in monitor_processes
      then waits for process to terminate in _monitor
    '''
    
    init = self.set_state()
    while self._go:
      init = self.monitor_processes(init)
    self._set_proc_state()
    self._monitor()
    return
    
if os.name == 'nt': s = ProcSleuth('excel.exe')
else: s = ProcSleuth('firefox-esr')
s.run()
# this call creates the report
s._d3js_data_hub()
