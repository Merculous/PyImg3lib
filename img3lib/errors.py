
class Error(Exception):
    pass

class DataSizeMismatch(Error):
    pass

class ChecksumMismatch(Error):
    pass

class AlignmentError(Error):
    pass

class VariableEmpty(Error):
    pass

class InfoError(Error):
    pass

class LZSSError(Error):
    pass

class ModeError(LZSSError):
    pass

class Img3Error(Error):
    pass

class TagError(Img3Error):
    pass
