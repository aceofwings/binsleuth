from binsleuth.core.operation import Operation
import os
import hashlib
import logging

logger = logging.getLogger(__name__)

PRIMARY_HASH_BUFFER_SIZE = 8192
SECONDARY_HASH_SIZE = 512

class FileMetaData(Operation):

    """
    Operations for pulling metadata are placed here.
    Hashing uses sha1 to pull a unique identifier for the file being operated on
    """

    project_settings = {}

    def __init__(self,project,config,**kwargs):
        self.project = project
        self.sm = project.factory.simulation_manager(save_unconstrained=True,**kwargs)

    def run(self):
        """
        run metadata collection a file. Collects hash information and size
        """
        logger.info("Determing File Metadata for " + self.project.filename)
        self.size = self.fileSize().st_size
        self.maglabel = "BYTES"

        for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
            if self.size < 1024.0:
                self.maglabel = x
                break
            self.size /= 1024.0

        self.primaryHash = self.getFilePrimaryHash()
        self.secondaryHash = self.getFileSecondaryHash()
        logger.info(""""
        INFORMATION : {}
        File Size : {:.2f} {}
        Primary ID : {}
        Secondar ID : {}
        """.format(self.project.filename, self.size,self.maglabel,self.primaryHash, self.secondaryHash))

    def fileSize(self):
        """
        Reutnr the size of the file in bytes
        """
        return os.stat(self.project.filename)

    def getFilePrimaryHash(self):
        """
        Hash the entire file in order to produce a unique identifer
        """
        hashfunc = hashlib.sha1()
        with open(self.project.filename, 'rb') as f:
            buffer = f.read(PRIMARY_HASH_BUFFER_SIZE)
            while len(buffer) != 0:
                hashfunc.update(buffer)
                buffer =  f.read(PRIMARY_HASH_BUFFER_SIZE)
            return hashfunc.hexdigest()

    def getFileSecondaryHash(self):
        """
        Hash only the first 512 bytes of a file to produce an identifer
        """
        hashfunc = hashlib.sha1()
        with open(self.project.filename,'rb') as f:
            buffer = f.read(SECONDARY_HASH_SIZE)
            hashfunc.update(buffer)

        return hashfunc.hexdigest()
