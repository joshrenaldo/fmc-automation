from fireREST.fmc import Connection
from fireREST.fmc.policy.prefilterpolicy.operational.hitcounts import Hitcount


class Operational:
    def __init__(self, conn: Connection):
        self.hitcount = Hitcount(conn)
