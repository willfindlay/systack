import os

PROJECT_PATH = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
BPF_PATH = os.path.join(PROJECT_PATH, 'systack/bpf/bpf_program.c')
