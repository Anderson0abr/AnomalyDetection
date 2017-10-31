import threading

class MyThread(threading.Thread):
    def __init__(self, _func, _args):
        threading.Thread.__init__(self)
        self.func = _func
        self.args = _args

    def run(self):
        threading._start_new_thread(self.func, self.args)