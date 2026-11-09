import subprocess

from baitbox.sandbox import BOX

HELP = "run one command in the sandbox: baitbox box <net|nonet> <project> <box> <seconds> <command>"


def main(argv):
    return subprocess.call(["bash", str(BOX), *argv])
