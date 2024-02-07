from multiprocessing import Process
from scapytest import start_ids

def run_instance(instance_id, port):
    output_filename = f"alerts_instance_{instance_id}_port_{port}.log"
    start_ids(port=port, output_filename=output_filename)

if __name__ == "__main__":
    ids_processes = []
    base_port = 10000  # Starting port number

    for i in range(100):
        port = base_port + i
        p = Process(target=run_instance, args=(i, port))
        ids_processes.append(p)
        p.start()

    for p in ids_processes:
        p.join()
