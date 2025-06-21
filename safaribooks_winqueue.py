class WinQueue(list):
    """
    Multiprocessing queue workaround for Windows compatibility.
    Used when the standard multiprocessing.Queue causes pickling errors on Windows.
    """
    def put(self, el):
        self.append(el)

    def qsize(self):
        return self.__len__()
