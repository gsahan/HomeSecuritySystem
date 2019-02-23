#/usr/bin/python
# Author   : Gorkem Sahan
# Ver      : 2.0 
# last Upd : Config file, web interface 19.03.2016 18:26 
import sys
import RPi.GPIO as GPIO
import signal, os
import time
import threading
import thread
import Queue
import datetime
from twilio.rest import TwilioRestClient # pip install twilio
import ipgetter # pip install ipgetter
import socket
import re
import smtplib
from temprature import read_temp
import email
import imaplib
from Crypto.Cipher import DES # apt-get install python-dev , pip install pycrypto , pip install Crypto
import httplib

#pins -------------
GPIO_PIR = 21
BUZZER = 20 
BLUE_LED = 16
BUTTON_CLOSE = 12
SIREN_1 = 26

isAuth = Queue.Queue()
main_to_ex_ip_cnt = Queue.Queue()
Kill_All = Queue.Queue()
Web_Input = Queue.Queue()
Home_temprature = 0
_protection_status = "w" # w:waiting s:started
check_system_status_file = "hss_sec_strd.dat"
#user parameters ------------
phone_list = []
toaddrs  = []
mail_checker_list = []


#------------------------------------------------------------------------------------------ 
class AppConfigs():
    _configFile='App.Config'
    def AppKey(self,key):
        try:               
            if os.path.isfile(self._configFile):
                lines = self.__readfl(self._configFile)
                for line in lines:
                    line=line.strip('\n').strip()
                    m = re.search("""^(?P<key>(\w|_|-)+)=(?P<q>['"])(?P<value>.+)(?P=q)$""",line)
                    if m:
                        if  m.group('key') == key:
                            return m.group('value')
                        else:
                            pass# print( '>>'+m.group('key')+'<<'+key+'>>'+ m.group('value')+'<<')
                    else: 
                        print('APPCONFIG>>---- ---- ---- Invalid Config  :>>' + line+'<<' )
                    #if st is not None and st[0] == key:
                print('APPCONFIG>>Config not found.....:>>'+key+'<<')
                return ''  
            else:
                print("APPCONFIG>>-- Error !! -------------------- \n App.Config does not exists !\n------------------------------------\n")
                raise Exception('AppConfig Doesnt Exists.....')
        except:
            raise
    
    def __cozl(self,text):
        try:
            obj=DES.new(pssw, DES.MODE_ECB)
            return obj.decrypt(text)
        except:
            raise

    def __sfrl(text,pssw):
        try:
            obj=DES.new(pssw, DES.MODE_ECB)
            text = text+ (8-(len(text)%8))*' '
            return obj.encrypt(text)
        except:
            raise

    def __readfl(self,filename):
        try:
            fl = open(filename,'r')
            lines = fl.readlines()
            fl.close()
            return lines
        except:
            raise

    def __writefl(self,filename,value,mode='a'):
        try:
            fl = open(filename,mode)
            if type(value) is list:
                for elm in value:
                    fl.write(value+'\n')
            else:
                fl.write(value+'\n')
            fl.close
        except:
            raise

#---------------------------------------------------------------------------------------------------------------------------
def send_mail(message):
    try:
        appc = AppConfigs()
        fromaddr =  appc.AppKey('FROM_MAIL')#'xxx@gmail.com'
        username =  appc.AppKey('FROM_MAIL_USER')#'xx'
        password =  appc.AppKey('FROM_MAIL_PASSW')#
        smtpAddr =  appc.AppKey('FROM_MAIL_SMTP')# smtp.gmail.com:587
        notifSubject =  appc.AppKey('NOTIFIY_MAIL_SUBJECT')#Home Security System Notification 
        
        server = smtplib.SMTP(smtpAddr)
        server.starttls()
        server.login(username,password)
        server.sendmail(fromaddr, toaddrs,'Subject: '  + notifSubject + '  \n\n' + message)
        server.quit()
        print('\neMail sended : '+ message)
        return True
    except :
        print("\neMail cannot be sended")
        return False

def send_mail_to(mailaddr,subj,body):
    try:        
        appc = AppConfigs()
        fromaddr =  appc.AppKey('FROM_MAIL')
        username =  appc.AppKey('FROM_MAIL_USER')
        password =  appc.AppKey('FROM_MAIL_PASSW')
        smtpAddr =  appc.AppKey('FROM_MAIL_SMTP')

        # The actual mail send
        server = smtplib.SMTP(smtpAddr)
        server.starttls()
        server.login(username,password)
        server.sendmail(fromaddr, mailaddr,'Subject: '+subj+' \n\n' + body)
        server.quit()
        print('\neMail sended : '+subj+" "+mailaddr)
        return True
    except :
        print("\neMail cannot be sended")
        return False        

#-------------------------------------------------------------------------------------------------
class mail_Controller ( threading.Thread ):
    def run (self):
        print("\nMail Checker thread is up")
        try:
            appc = AppConfigs()
            eadd =  appc.AppKey('FROM_MAIL')            
            pd =  appc.AppKey('FROM_MAIL_PASSW')
            self.smtpAddr =  appc.AppKey('FROM_MAIL_SMTP')
            self.imapAddr =  appc.AppKey('IMAP_ADDR')
            self.imapPort =  appc.AppKey('IMAP_PORT')
            self.homeIdent = appc.AppKey('HOME_IDENTITY_KEY')                                   
            timeCnt = 0
            while True:
                try:                    
                    if not Kill_All.empty():
                        print("Mail checker closed...")
                        break
                    if timeCnt >= 10:
                        M = imaplib.IMAP4_SSL(self.imapAddr,self.imapPort)                        
                        M.login(eadd, pd)
                        M.select()
                        # print("mail okunuyor ....")
                        mails = ""
                        for emls in mail_checker_list:
                            typ, d = M.search(None,'UnSeen','SUBJECT','Hss:'+self.homeIdent,'From',emls)
                            if typ == 'OK':
                               mails = mails + d[0]
                        #print("Mail cevabi : "+ mails )
                        for num in mails.split():
                            typ, data = M.fetch(num, '(RFC822)')
                            msg = email.message_from_string(data[0][1])
                            body = msg.get_payload(decode=False)
                            if type(body) is list:
                                body = body[0].get_payload()
                            else:
                                matched = re.match('(\w+)\s', body) # Matched ?
                                if not matched:
                                    body = msg.get_payload(decode=True)
                                    if type(body) is list:
                                        body = body[0].get_payload() 
                            print("Mail alindi :\n>>"+body+"<<")
                            self.process_mail(body,msg["From"])
                            M.store(num,'+X-GM-LABELS','\\Trash')
                        M.close()
                        M.logout()
                        M = None
                        timeCnt = 0                    
                    else:
                        timeCnt = timeCnt +1
                    time.sleep(1)
                except Exception,e :
                    timeCnt=0
                    print("mail alinamyor, denemeye devam edecek hata: "+str(e))
                    #send_mail_to(eadd,self.homeIdent+' Mail Crashed',"Process kirildi.\n"+str(e))

        except Exception,e :
            print("mail alinamiyor,process kirilidi :"+str(e))
            send_mail_to(eadd,self.homeIdent+' Mail Crashed',"Process kirildi mail dinlenmiyor.\n"+str(e))
            raise
        
    def process_mail(self,body,emsender):
        match = re.match('(\w+)\s', body)
        if match:
            command = str(match.group(1)).lower()
            if command == "basla":
                self.start_prc(emsender)
            elif command == "bilgi":
                self.info_prc(emsender)
            elif command == "bitir":
                self.close_prc(emsender)  
            else:
                send_mail_to(emsender,self.homeIdent+' Unknown Cmd: '+command,body)
        else:
            send_mail_to(emsender,self.homeIdent+' Unknown/notMatched Cmd ',body)


    def close_prc(self,emsender):

        if _protection_status == 's':
            putisAuthChannel()
            send_mail_to(emsender,'HSS Close Cmd','HSS '+self.homeIdent+' Close Command Sended\n'+'HomeTemprature :'+str(Home_temprature)+"C\n" + time.ctime())
        else:
            send_mail_to(emsender,'HSS Close Cmd','HSS '+self.homeIdent+' Already Closed Sended\n'+'HomeTemprature :'+str(Home_temprature)+"C\n" + time.ctime())

    def start_prc(self,emsender):

        if _protection_status == 'w':
            Web_Input.put("start")
            send_mail_to(emsender,'HSS Start Cmd','HSS '+self.homeIdent+' Start Command Sended\n'+'HomeTemprature :'+str(Home_temprature)+"C\n" + time.ctime())
        else:
            send_mail_to(emsender,'HSS Start Cmd-Already Started','HSS '+self.homeIdent+' Already started\n'+ 'HomeTemprature :'+str(Home_temprature)+"C\n" +time.ctime())
    def info_prc(self,emsender):
        send_mail_to(emsender,'HSS Info Cmd','HSS '+self.homeIdent+' Info\n'+'Protect stat : '+_protection_status +'\nHomeTemprature :'+str(Home_temprature)+"C\n" +time.ctime()+ " ip : "+ External_ip_cnt_thread._ip)

    def spy_mode_prc(self,emsender):
        pass
#--------------------------------------------------------------------------------------------------------
class temprature_checker ( threading.Thread ):

    def run (self):
        print("\nTempreture thread is up")
        global Home_temprature
        timeCnt = 60
        while True:
            if not Kill_All.empty():
                break            
            Home_temprature ,fahrenaight = read_temp()
            if Home_temprature >= 48 :
                send_mail("home tempr : "+str(Home_temprature))
            if timeCnt >= 60:
                timeCnt = 0
                appc = AppConfigs()
                #allowFileExtensions = appc.AppKey('WEB_FILE_EXTENSIONS')
                rootDir = appc.AppKey('WEB_FILE_ROOT').strip('/')+'/'
                self.__writefl(rootDir+"hometemprature.dat",time.ctime()+','+str(Home_temprature))
            timeCnt = timeCnt+1
            time.sleep(1)
        print("\nTempreture thread closed...")
            
    def __writefl(self,filename,value,mode='a'):
        try:
            fl = open(filename,mode)
            if type(value) is list:
                for elm in value:
                    fl.write(value+'\n')
            else:
                fl.write(value+'\n')
            fl.close
        except:
            raise
    
#----------------------------------------------------------------------------------------------
class vpn_service(threading.Thread):

    _iisPort = 9399
    _masterPort = 9398
 
    def close(self):
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('localhost',self._iisPort))
            sock.sendall('exit')
            print('VPN_SERVICE>>CLOSE COMMAND SENT')
        except Exception,e:
            print('VPN_SERVICE>>CLOSE EXCEPTION :'+str(e))
        finally:
            sock.close()

    def run(self):
        try:
            print('VPN_SERVICE>>STARTING')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            iis = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('',self._masterPort))
            iis.bind(('',self._iisPort))
            iis.listen(1)
            cs = None
            csHS = None
                
            while 1:
                try:
                    if not Kill_All.empty():
                        break
                    cs,ca = iis.accept()
                    cs.settimeout(45)
                    req = cs.recv(1024)
                    print('VPN_SERVICE>>IIS GOT REQUEST :')
                    print(req[:30])
                    if not req == b'' and not req == 'exit' :
                        print('VPN_SERVICE>>ROUTING TO SLAVE')
                        sock.listen(1)
                        sock.settimeout(30)#30 sec to read
                     
                        procOk = False
                        cntTry = 0
                        statuSlavePi = 't'
                        while not procOk:
                            csHS,caHS = sock.accept()#salve pi
                            statuSlavePi = 'c'                         
                            print('VPN_SERVICE>>CONNECTED TO SLAVE')
                            csHS.settimeout(40)
                            csHS.sendall(req)
                            fn = False
                            resp = ''
             
                            while not fn :
                                respp = csHS.recv(1024)
                                if respp == b'':
                                    fn = True
                                else:
                                    resp = resp+respp
                            if not resp == '':
                                procOk = True
                            else:
                                print('VPN_SERVICE>>RESPONSE NULL,ROUTED AGAIN')
                                cntTry = cntTry +1
                                
                                if cntTry > 2:
                                    resp = 'HTTP/1.0 200\n\nNO RESPONSE TRY OF '+str(cntTry)
                                    print('VPN_SERVICE>>'+resp)
                                    break
                                else:
                                    time.sleep(0.2)
                        print('VPN_SERVICE>>READY TO RESPONSE')
                        cs.sendall(resp)
                        print('VPN_SERVICE>>SUCCESS RESPONSED\n')        
                        csHS.close()
                       
                    cs.close()

                except Exception,e:
                   try:
                       print('VPN_SERVICE>>EXCEPTION HANDLED:'+str(e))
                       if statuSlavePi == 't' and not cs == None:
                           cs.sendall('HTTP/1.0 200\n\nSlave pi doesnt connect...')
                       elif  statuSlavePi == 't' :
                           send_mail('Slave pi cannot connect...'+str(e))
                       if not cs == None:
                           cs.sendall(str(e))                           
                   except:
                       pass
                   finally:
                       if not cs == None:                           
                           cs.close()
                       if not csHS == None:
                           csHS.close()
                            
            sock.close()
            iis.close()
            print('VPN_SERVICE>>CLOSED')
        except Exception,e:
            send_mail_to('berksahan@gmail.com','VPN Service Crashed',"vpn Process crached, fatalerror  : \n"+str(e))
            sock.close()
            iis.close()
            print('VPN_SERVICE>>CRASHED DETAILS:'+str(e))

    
#--------------------------------------------------------------------------------------------------------
class web_Interface ( threading.Thread ):
   _sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   _system_output = []
   host = '' # socket.gethostname()
   port = 9390

   def close(self):
      try:
          self._sock.close()
          print("WEB_INTERFACE>>socked bye sending")
          self.clsSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          self.clsSocket.connect(('localhost',self.port))
          self.clsSocket.send('bye')
      except :
          pass
      finally :
          self.clsSocket.close()


   def set_output(self,message):
      if len(self._system_output) > 50 :
          try:
              self._system_output.remove(self._system_output[len(self._system_output)-1])
          except :
              pass
	  #for i in self._system_output:
          #    self._system_output.remove(i)
          #    break

      self._system_output = [' '+message] +  self._system_output

   def __readfl(self,filename):
      try:
          fl = open(filename,'r')
          lines = fl.read()
          fl.close()
          return lines
      except:
          raise

   def __readflBn(self,filename):
      try:
          appc = AppConfigs()
          #allowFileExtensions = appc.AppKey('WEB_FILE_EXTENSIONS')
          rootDir = appc.AppKey('WEB_FILE_ROOT').strip('/')+'/'
          if os.path.isfile(rootDir+filename):
              #print("--------------------- > file exits :"+rootDir+filename)
              file = open(rootDir+filename,'rb')
              fileBytes = file.read()
              file.close()
              return fileBytes
          else:
              #print("--------------------- > file not exists :"+rootDir+filename)
              return b''
 
      except:
          raise
   def run ( self ):
      # Standard socket stuff:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self._sock = sock
      sock.bind((self.host, self.port))
      sock.listen(1) # don't queue up any requests

      # Loop forever, listening for requests:
      print("\nWEB_INTERFACE>>Web interface up ...")
      while True:
         try:
             if not Kill_All.empty():
                 break
             csock, caddr = sock.accept()
             print ("\nWEB_INTERFACE>>Web Connection "+time.ctime())
             print (caddr)
             csock.settimeout(60)
             req = csock.recv(2048) # get the request, 2kB max
             #print (req)
             if req == b'' :
                 print("WEB_INTERFACE>>request null, connection closed !!!")
                 csock.close()
             match = re.search('(?P<method>GET|POST) (?P<url>(/(\w|\.|\-|_)+)+)(\?(?P<req>(\w|=|&)+))?',req)
             #match = re.search('(?P<method>GET|POST) (?P<url>(/\w+)+)(\?(?P<req>(\w|=|&)+))?\sHTTP/',req)
             #matchGET = re.match('GET /HSS/(\w+)\sHTTP/1', req)
             #matchPOST = re.match('POST /HSS/(\w+)\sHTTP/1', req)
             #method = ""
             
             if match:
                 virtualWebPath = match.group('url')
                 method = match.group('method')
                 requestString = match.group('req')
                 print('WEB_INTERFACE>>method-URL:'+method+'>>'+virtualWebPath+'\n')
             else:
                 virtualWebPath = ''
                 method='-'
                 requestString='-'
                 print('WEB_INTERFACE>>Unknown req:\n'+req)

             if virtualWebPath != '':        
                 
                 if method == "GET" and virtualWebPath == "/HSS/gs":
                     response = self.__readfl('main.ghtm').replace('TEMP_TAG',str(Home_temprature))
                     response = response.replace('SYSTEM_OUTPUT',"<br/>".join(self._system_output))
                     if _protection_status == "w":
                         response = response.replace('BUTTON_VISIBLE','src="start.png"')
                     else:
                         response = response.replace('BUTTON_VISIBLE','src="locked.png" disabled="disable"')
                     csock.sendall(response)
                     csock.close()
                 elif method == "GET" and virtualWebPath =="/HSS/tempgraph":
                     response = self.__readfl('tempgraph.ghtm')
                     csock.sendall(response)
                     csock.close()
                 elif method == "GET" and virtualWebPath =="/HSS/exit":
                     response =  self.__readfl('exit.ghtm')
                     csock.sendall(response)
                     csock.close()
                     
                 elif method == "GET" and virtualWebPath == "/HSS/xml_voice" :
                     response =  self.__readfl('xml_voice.ghtm')
                     csock.close()
                 #start command
                 elif method == "POST" and virtualWebPath == "/HSS/start":
                     response = self.__readfl('main.ghtm').replace('TEMP_TAG',str(Home_temprature))
                     if _protection_status == "w":
                         appc = AppConfigs()
                         delay_counter =int(appc.AppKey('START_DELAY'))
                         Web_Input.put("start")
                         scriptReload = '<script type="text/javascript">var timer = '+str(delay_counter+1)+'; function reloadIt(){ if(timer<=0){window.location="../HSS/gs";} else{ timer = timer-1; document.getElementById("starttimer").innerHTML ="Starting in "+timer+" sec"; setTimeout(reloadIt,1000);}} reloadIt();</script>'
                         response = response.replace('SYSTEM_OUTPUT',"<p id='starttimer'> Starting...</p>"+scriptReload+"<br/>".join(self._system_output))
                         response = response.replace('BUTTON_VISIBLE','src="locked.png" disabled="disable"')   
                     elif _protection_status == "s":
                         response = response.replace('SYSTEM_OUTPUT',"<h3>Protection has been activated before.</h3><br/>"+"<br/>".join(self._system_output))
                         response = response.replace('BUTTON_VISIBLE','src="locked.png" disabled="disable"')

                     csock.sendall(response)
                     csock.close()
                 #Apple touch icon
                 elif method=='GET' and ( virtualWebPath  =='/favicon.ico'  or  virtualWebPath == '/apple-touch-icon-120x120-precomposed.png' or virtualWebPath =='/apple-touch-icon-152x152-precomposed.png') :
                     PNGico = self.__readflBn('rsbbry.png')
                     csock.sendall(PNGico)
                     csock.close()
                 elif method=='GET' and  virtualWebPath  == '/HSS/close/03122016':
                     Kill_All.put(True)
                     csock.sendall('Access Granted!')
                     csock.close()
#beacon *******
                 elif method=='GET' and  virtualWebPath  == '/HSS/exitregion':
                     print("<<<<<<<<<<<<<<<exitregion")
                     csock.send('HTTP/1.0 200\nContent-Type: text/html\n\n')
                     if _protection_status == 'w':
                         Web_Input.put("start")
                         csock.sendall('{"result":"started"}')
                     else:
                         csock.sendall('{"result":"alreadystarted"}')                    
                     
                     csock.close()
                 elif method=='GET' and  virtualWebPath  == '/HSS/closedimmadiate2k5j':
                     if _protection_status == 's': 
                         beaconSound().start()
                         putisAuthChannel()
                     csock.send('HTTP/1.0 200\nContent-Type: text/html\n\n')
                     print("<<<<<<<<<<<<<<<immadiate")
                     csock.sendall('{"result":"closed"}')
                     csock.close()
                 elif method=='GET' and  virtualWebPath  == '/HSS/near':
                     print("<<<<<<<<<<<<<<<near")
                     #putisAuthChannel()
                     #ok_Sound().start()
                     csock.send('HTTP/1.0 200\nContent-Type: text/html\n\n')
                     csock.sendall('{"p":"near"}')
                     csock.close()
 #end beacon ********
#baymak logs     
                 elif method == 'GET' and virtualWebPath[0:12]  == '/baymak/log/' :
                     fbaymak = open('baymaklog.log','a')
                     fbaymak.write('\"'+time.ctime()+'\",'+virtualWebPath[12:]+'\n')
                     fbaymak.close()
                     csock.send('HTTP/1.0 200\nContent-Type: text/html\n\n')
                     csock.sendall('OK '+time.ctime())
                     csock.close()
                 elif method == 'GET':# spesifik bir dosya talep edildi ise ...                                                             
                     fl = re.search('/HSS/(?P<fl>(\w|\-|&|\?|\)|\(|\+|\!)+\.(?P<ext>dat|js|png|gif|ico|jpeg|jpg|pdf)$)',virtualWebPath)
                     if fl:
                         #appc = AppConfigs()
                         #allowFileExtensions = appc.AppKey('WEB_FILE_EXTENSIONS')                        
                         filename = fl.group('fl')   
                         print("WEB_INTERFACE>>Requested File : "+filename)
                         filebt = self.__readflBn(filename)
                         if not filebt == b'':
                             csock.send('HTTP/1.0 200\nContent-Type: text/html\n\n')
                             csock.sendall(filebt)
                             csock.close()
                         else:
                             print("WEB_INTERFACE>>404 TO >> FILE NOT EXITS  method="+method+" file="+filename)
                             response =  self.__readfl('404.ghtm')
                             csock.sendall(response)
                             csock.close()
                     else:
                         print("WEB_INTERFACE>>404 TO MISMATCH WEB_APP/FILE_EXTENSION  >> method="+method+" virtualpath="+virtualWebPath)
                         response =  self.__readfl('404.ghtm')
                         csock.sendall(response)
                         csock.close()
                         
                 else:
                     print("WEB_INTERFACE>>404 TO >> method="+method+" virtualpath="+virtualWebPath)
                     response =  self.__readfl('404.ghtm')
                     csock.sendall(response)
                     csock.close()
             else:
                 # If there was no recognised command then close connection
                 print ("\nWEB_INTERFACE>>404  for this request :")
                 print (req)
                 print("\n*******************************\n")
                 response =  self.__readfl('404.ghtm')
                 csock.sendall(response)
             csock.close()
         except Exception,e:
             print("\nWEB_INTERFACE>>error: connection lost with client :\n"+str(e))
             csock.close()
             
      #end While loop
      print("\nWEB_INTERFACE>>Closed...")


#------------------------------------------------------------------------------------------

class ok_Sound ( threading.Thread ):
   def run ( self ):
       try:
          i = 0
          while i < 5:
             GPIO.output(BUZZER,GPIO.HIGH)
             time.sleep(0.06)
             GPIO.output(BUZZER,GPIO.LOW)
             time.sleep(0.03)
             i = i+1

       except Exception:
          pass

class beaconSound ( threading.Thread ):
   def run ( self ):
       try:
          i = 0
          while i < 10:
             GPIO.output(BUZZER,GPIO.HIGH)
             time.sleep(0.1)
             GPIO.output(BUZZER,GPIO.LOW)
             time.sleep(0.4)
             i = i+1

       except Exception:
          pass

class motion_Sound ( threading.Thread ):
   def run ( self ):
      try:
         i = 0
         time.sleep(0.4)
         while i < 3:
            GPIO.output(BUZZER,GPIO.HIGH)
            time.sleep(0.1)
            GPIO.output(BUZZER,GPIO.LOW)
            time.sleep(0.1)
            i = i+1
      except Exception:
         pass

#----------------------------------------------

class command_Thread (threading.Thread) :
   _isAuth = 0
   _start_Flag = 0
   def run( self ) :
      try:
         isOk = False
         while not isOk :
            try:
               Comm = raw_input('Enter Command :\n')
               if Comm == "ok" :
                  putisAuthChannel()
                  self._isAuth = 0
                  ok_Sound().start()
                  print("Access granted!")
	       elif Comm == "start":
                  self._start_Flag = 1
               elif Comm == "bye" :
                  print ("Good Byee................")
                  Kill_All.put(True)
                  return
	       else :
                  print ("Wrong Command !!\n\n")
	    except KeyboardInterrupt:
               	print ("Wrong Command...")
      except KeyboardInterrupt:
         print ("Wrong command ......")

   def isAuthanticateSuccess(self):
	  if self._isAuth == 0:
		 return False
	  else:
                 self._isAuth = 0
		 return True

   def isStartCommand(self):
          if self._start_Flag == 1:
             self._start_Flag = 0
             return True
          else:
             return False

# authentication is success , to all threads
def putisAuthChannel():
   isAuth.put(True)


class Close_button ( threading.Thread ):
   _Pressed = False
   def run ( self ):
	  try:
		 i = 0
		 PRESSED = 0
		 while i < 150 :
			PRESSED = GPIO.input(BUTTON_CLOSE)
			i = i+1
			if PRESSED == 1 :
			   time.sleep(1)
			   if GPIO.input(BUTTON_CLOSE) == 1:
				  self._Pressed = True
				  print("Close button pressed")
				  putisAuthChannel()
				  ok_Sound().start()
				  break
			   else :
				  PRESSED = 0
				  i = i+10
                        time.sleep(0.1)
		 print("\nButton Thread closed...")

	  except Exception:
		 pass

   def isPressed(self):
	  return self._Pressed




#----------------------------------------------




class Alarm_Thread (threading.Thread) :
   def run( self ) :
	  alarm_start(13,60*3) # wait 13 sec, alarm fired 3 min

def alarm_start(delay, alarm_time):
   while True:
	  if isAuth.empty() : # passw waiting
		 if delay:
			time.sleep(1)
			delay = delay -1
			if delay <= 0:
			   Warning_Thread().start()
		 else: # alarm
			while alarm_time > 0 and isAuth.empty():
                           alarm_open()
			   alarm_time = alarm_time - 0.2
			   time.sleep(0.2)
			   if alarm_time <= 0:
                              alarm_close()
                              print ("\nAlarm time out...")
			      return 0

	  else:
             alarm_close()
             print ("\nAlarm closed with Access granted...")
             break

   print ("\nAlarm Closed...")
   return 1


def alarm_open():
   GPIO.output(SIREN_1,GPIO.LOW)

def alarm_close():
   GPIO.output(SIREN_1,GPIO.HIGH)



#-----------------------------------------------------------------------------
class Warning_Thread (threading.Thread) :
   def run( self ) :
	  send_sms("Alarm triggered",True)
	  print ("\nSMS sended...\n")
	  send_mail("Alarm Triggered")


#------------------------------------------------------------------------------------------------

class DynDnsSettler(threading.Thread):
   def run(self):
       print "\nDYNAMIC_DNS>>Settler Started"
       while True:
           if not Kill_All.empty():
               break
           self.__setDynamicDns()
           time.sleep(15)
       print "\nDYNAMIC_DNS>>Closed"

   def __setDynamicDns(self):
       try:
           appc = AppConfigs()
           dnsAdress =  appc.AppKey('DYNAMIC_DNS_ADRESS')
           dnsParams =  appc.AppKey('DYNAMIC_DNS_PARAMETES')
           dnsDomain =  appc.AppKey('DYNAMIC_DNS_DOMAIN')
           dnsToken  =  appc.AppKey('DYNAMIC_DNS_TOKEN')
           dnsMethod =  appc.AppKey('DYNAMIC_DNS_METHOD')
           dnsParams =  dnsParams.replace('CD_DOMAIN',dnsDomain).replace('CD_TOKEN',dnsToken)
           #print("DNS :: "+dnsAdress+dnsParams)
           c = httplib.HTTPSConnection(dnsAdress)
           c.request(dnsMethod,dnsParams )
           response = c.getresponse()
           if response.status == 200 and response.read() == 'OK':
               print('Dynamic Dns OK.'+time.ctime())
           else:
               print('dynamic dns cannot set.'+str(response.status)+time.ctime())
               send_mail('Dynamic dns cannot set status:'+str(response.status))

       except Exception,e:
           print('dynamic dns failed:'+str(e))
           send_mail('DDere DNS cannot set error :\n'+str(e))

#-----------------------------------------------------------------------------------------------------------

class External_ip_cnt_thread (threading.Thread) :
   _last_ip = ""
   _ip = ""
   _cnt = 0
   _main_query_site = "http://www.whatsmyipaddress.net"
   def run( self ) :
	  print "\nSearching External IP adress ..."              
	  while True:
		 self._cnt = self._cnt+5
		 if not main_to_ex_ip_cnt.empty():
			if main_to_ex_ip_cnt.get() == "close":
			   break
                 
		 if self._cnt >= (60*10) or self._last_ip == "": # waiting periyod min 10 min
			self._cnt = 0
                        print('IP checking... '+time.ctime())
			if self._last_ip == "":
                            self.isfirst =True
                        else:
                            self.isfirst =False   
			#self._ip = ipgetter.IPgetter().fetch(self._main_query_site)
			self._ip = ipgetter.myip()
			while self._ip == "127.0.0.1" or self._ip == '' or self._ip == None:
                            if not main_to_ex_ip_cnt.empty():
                                print("\nIP Check thread closed try to find ip")
                                return
                            print("\nCouldn't find external ip, trying in random sites... :"+self._ip+"\n")
                            self._ip = ipgetter.myip()
                            
                            
                        print('IP : '+ self._ip+' '+time.ctime()+'\n\r\n\r')
			if self._ip != self._last_ip  :
                            self._last_ip = self._ip
                            appc = AppConfigs()
                            dnsAdress =  'http://'+appc.AppKey('DYNAMIC_DNS_DOMAIN')+'.'+appc.AppKey('DYNAMIC_DNS_ADRESS').replace('www.','')+':9390/HSS/gs'
                            if self.isfirst :
                                self.message_prefix = "Home Security System is UP IP: : "
                            else:
                                self.message_prefix = "Home New IP  : "
                            if(not send_mail(self.message_prefix+"\nhttp://"+ self._ip+":9390/HSS/gs \n"+dnsAdress)):
                                send_sms(self.message_prefix+"\nhttp://"+ self._ip+":9390/HSS/gs \n"+dnsAdress)
                        External_ip_cnt_thread._ip = self._ip 
		 time.sleep(5)
	  print("\nIP Check thread closed")
	  
   def getExtIp(self):
      return self._ip

#------------------------------------------------------------------------------------------




def send_sms(message,vcall = False):

   appc = AppConfigs()      
   ACCOUNT_SID = appc.AppKey('TW_ACCN')
   AUTH_TOKEN  = appc.AppKey('TW_TOKEN')
   fromPhone = appc.AppKey('TW_PHONE')
   client = TwilioRestClient(ACCOUNT_SID, AUTH_TOKEN)

   for phone in phone_list :
      try :

          client.messages.create(  to= phone, from_=fromPhone,body=message)
          time.sleep(1.1)

          if vcall :
             call = client.calls.create(
                  to= phone,
                  from_=fromPhone,
                  url="https://demo.twilio.com/welcome/voice/",
                  method="GET",
                  fallback_method="GET",
                  status_callback_method="GET",
                  timeout="60",
                  record="false")
      except:
          print("\nsms-call error for "+ phone)

#-------------------------------------------------------------------------------------------

def start_delay():
   delay_counter = 20
   try:
       appc = AppConfigs()   
       delay_counter = int(appc.AppKey('START_DELAY'))
   except:
       delay_counter = 20
       print("Configration of START_DELAY invalid. it is default 20") 
   print ("\nSystem is starting in "+str(delay_counter)+" sec")
   while delay_counter >= 2:
      #sys.stdout.write('\r\b'+str(delay_counter))
      #sys.stdout.flush()
      GPIO.output(BUZZER,GPIO.HIGH)
      time.sleep(0.1)
      GPIO.output(BUZZER,GPIO.LOW)
      fr = delay_counter * 0.03
      time.sleep(fr)
      delay_counter = (delay_counter - ( 0.1 + delay_counter*0.03 ))
   GPIO.output(BUZZER,GPIO.HIGH)
   time.sleep(2)
   GPIO.output(BUZZER,GPIO.LOW)

def start_statu_control():
    if  (not Web_Input.empty() and Web_Input.get() == "start"):
        return True
    else:# started file control
       if( os.path.isfile(check_system_status_file) ):
           return True
        
    
    return False
    
    
########################################################################################################################
#############  START MAIN PROCESSS ####################################################################################
########################################################################################################################

def signal_handler(signum, frame):
  print ("\r\binvalid command..")#'Signal handler called with ',signum

def main_proc():

   appc = AppConfigs()
   p_phones =  appc.AppKey('TO_PHONES').split(';')
   p_mailaddrs = appc.AppKey('TO_MAILS').split(';')
  
   global mail_checker_list
   mail_checker_list = appc.AppKey('GETFROM_MAILS').split(';')
 
   if len(p_phones) > 0 :
       global phone_list
       phone_list = p_phones
       print("---Phones : \n"+str(phone_list))
   else :
       print ("#### We need Phone list ... ###")
       return

   if len(p_mailaddrs) > 0:
       global toaddrs
       toaddrs = p_mailaddrs
       print("---Mail list : \n"+str(toaddrs))
   else:
       print (" ### We need Mail list ... ###")
       return

   signal.signal(signal.SIGINT,signal_handler)

   GPIO.setmode(GPIO.BCM)
   GPIO.setwarnings(False)

   # Set pin as output
   GPIO.setup(BUZZER,GPIO.OUT)
   GPIO.setup(BLUE_LED,GPIO.OUT)
   GPIO.setup(SIREN_1,GPIO.OUT)
   # Set pin as input
   GPIO.setup(GPIO_PIR,GPIO.IN)
   GPIO.setup(BUTTON_CLOSE,GPIO.IN,GPIO.PUD_DOWN)


   GPIO.output(BUZZER,GPIO.LOW)
   GPIO.output(BLUE_LED,GPIO.LOW)
   GPIO.output(SIREN_1,GPIO.HIGH)


   print ("################# SYSTEM UP ###################\n"+time.ctime()+"\n")

   Current_State  = 0
   global _protection_status

   try:

      External_ip_cnt_thread().start();

      com = command_Thread()
     #com.start()

      DynDnsSettler().start()

      web_face = web_Interface()
      web_face.start()

      vpnService = vpn_service()
      vpnService.start()

      temprature_checker().start()

      mail_Controller().start()

      #sys.stdout.write('Press The Button to Start Protection')
      #sys.stdout.flush()
      print("\nSystem waiting for start command...")
      web_face.set_output("System Waiting for Start " +time.ctime())
      while True:

              start_command = 0
              start = GPIO.input(BUTTON_CLOSE)
              #sys.stdout.write('\r\bPress The Button to Start Protection')
              #sys.stdout.flush()
              time.sleep(0.3)

              if not Kill_All.empty():
                 break;

              if start == 0 and ( com.isStartCommand() or start_statu_control() ) :
                     start = 1

              if start == 1  :
                      web_face.set_output("Protection starting... "+time.ctime())
                      fo = open(check_system_status_file,'a')# system start file olustur
                      fo.write("\nProtection starting... "+time.ctime())
                      fo.close()
                      _protection_status = "s"
                      start_delay()                                            
                      GPIO.output(BLUE_LED,GPIO.HIGH)
                      with isAuth.mutex:
                              isAuth.queue.clear()
                      print ("\nWaiting for PIR to settle ...")
                      while GPIO.input(GPIO_PIR)==1:
                          Current_State  = 0
                      print ("\nPIR Ready")
                      web_face.set_output("Protection mode has been activated at "+time.ctime())
                      print ("\nProtection mode has been activated ..."+time.ctime()+"\n")



              while start == 1 :

                     # Read PIR state
                     Current_State = GPIO.input(GPIO_PIR)

                     if Current_State==1 :

                            # PIR is triggered
                            print ("Motion detected! "+time.ctime())
                            web_face.set_output("<font color=\"Red\">Motion detected! "+time.ctime()+"</font>")
                            motion_Sound().start()

                            cls_btn = Close_button()# butona 1 sn basilirsa kapanir , 20sn icinde
                            cls_btn.start()

                            if com.isAuthanticateSuccess() == True :
                                   break

                            alarmthread = Alarm_Thread()
                            alarmthread.start()
                            alarmthread.setName("AlarmThread")
                            alarmthread.join() #alarm bitmesi bekleniyor                            

                            if not isAuth.empty():
                                   GPIO.output(BLUE_LED,GPIO.LOW)
                                                                      
                                   with isAuth.mutex:
                                      isAuth.queue.clear()
                                   web_face.set_output("<font color = \"green\">Protection mode off - Access granted " +time.ctime()+"</font>")
                                   print("button waiting")
                                   while GPIO.input(BUTTON_CLOSE) == 1:# butona basili tutulursa cekilmedigi surece bekle
                                       pass
                                   print("button released")
                                   time.sleep(1)
                                   break

                            time.sleep(5)

                            print ("There is No Access Granted !! System Reactivated...")
                            web_face.set_output("No Access granted !! System Reactivated : "+time.ctime())

                     else:
                            if not isAuth.empty() :
                                   with isAuth.mutex:
                                      isAuth.queue.clear()
                                   web_face.set_output("Protection mode off - Access Granted " +time.ctime())
                                   break
                            time.sleep(0.2)

              GPIO.output(BLUE_LED,GPIO.LOW)
              _protection_status = "w"
              if( os.path.isfile(check_system_status_file) ):
                  os.remove(check_system_status_file)#start file delete
              


      main_to_ex_ip_cnt.put("close")
      GPIO.cleanup()
      print ("<---- System Shutduwn ---->"+time.ctime())
      web_face.close()
      vpnService.close()


   except KeyboardInterrupt:
     #buzzer_Exit()
     print ("keyboard interrupt..."+time.ctime())
     main_to_ex_ip_cnt.put("close")

     # Reset GPIO settings
     GPIO.cleanup()
