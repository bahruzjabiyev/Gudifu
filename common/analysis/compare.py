from sys import argv
import glob
from multiprocessing import Process, Queue
from collections import Counter

class Comparer:
  def __init__(self, server_names, target_dir="/logs/", output_format="json"):
    if not target_dir.endswith("/"):
      print("The directory path should have '/' in the end.")
      exit()
    self.target_dir = target_dir
    self.server_names = server_names
    self.output_format = output_format

  def get_request_body(self, request):
    return b'\r\n\r\n'.join(request.split(b'\r\n\r\n')[1:])

  def compare(self, _hash, individual=False):
    """
    Takes a single hash. Based on this hash
    it gets the input request and the corresponding
    forwarded requests. Returns the list of
    additions, deletions and modifications done
    by each forwarded request on the input request.

    :param _hash: the value based on which the
    comparison happens.
    :param individual: enables comparison for
    an individual hash without a need for the
    comparison of the whole directory.
    """
    try:
      with open(f'{self.target_dir}input_{_hash}', 'rb') as inputf:
        input_request = inputf.read().lower()
    except FileNotFoundError:
      return []
    if not input_request:
      return []
    result = {}
    if individual:
      hash_server_names = [filename.split('/')[-1].split('_')[0] for filename in glob.glob(f'{self.target_dir}*_{_hash}')]
    else:
      hash_server_names = [filename.split('/')[-1].split('_')[0] for filename in self.hash_files[_hash]]
    hash_server_names.remove("input")
    if not hash_server_names:
      return []

    for server_name in hash_server_names:
      result[server_name] = {'additions': [], 'deletions': [], 'modifications': []}
      with open(f'{self.target_dir}{server_name}_{_hash}', 'rb') as inputf:
        result[server_name]["request"] = inputf.read().lower()
      with open(f'{self.target_dir}{server_name}_{_hash}', 'rb') as inputf:
        result[server_name]["request"] = inputf.read().lower()

    input_headers = input_request.split(b'\r\n\r\n')[0].split(b'\r\n')
    input_request_body = b''
    if b'\r\n\r\n' in input_request:
      input_request_body = self.get_request_body(input_request)

    for server_name in hash_server_names:

      headers_block = result[server_name]['request'].split(b'\r\n\r\n')[0]
      request_body = b''
      if b'\r\n\r\n' in result[server_name]['request']:
        request_body = self.get_request_body(result[server_name]['request'])

      for linenum, line in enumerate(headers_block.split(b'\r\n')):
        if line in input_headers:
          continue
        if linenum == 0: #request line
          result[server_name]["modifications"].append(input_headers[0] + b'----' + line)
        else:
          if b':' not in line:
            result[server_name]["additions"].append(line)
          else:
            loc = line.find(b':')
            header_name = line[:loc]
            header_value = line[loc:]
            # get the whole header from the input request using header name
            headers = [line for line in input_headers if line.startswith(header_name + b':')]
            if len(headers) == 0:
              result[server_name]["additions"].append(line)
            elif len(headers) == 1:
              result[server_name]["modifications"].append(headers[0] + b'----' + line)

            else:
              result[server_name]["modifications"].append(b'----'.join(headers) + b'----' + line)

      for line in input_headers:
        if line in headers_block:
          continue
        # see if any modification contains the line
        if True not in [line in modification for modification in result[server_name]["modifications"]]:
          result[server_name]["deletions"].append(line)

      if request_body != input_request_body:
        result[server_name]["modifications"].append(input_request_body + b'----' + request_body)

    if self.output_format == "awkable":
      output = []
      for server_name in result:
        for operation in ["additions", "deletions", "modifications"]:
          for item in result[server_name][operation]:
            output.append(f'{operation} ::::: {_hash} ::::: {server_name} ::::: {item}')
      return output

    return result

  def processHashes(self, hashes, quot):
    """
    Takes the list of hashes and returns
    a the comparison results for them.

    :param hashes: the list of hash values
    :param quot: this is a queue shared by
    multiple processes.
    """
    result = []
    for _hash in hashes:
      result.append(self.compare(_hash))

    quot.put(result)


  def compareDir(self):
    """
    Does a comparison on the whole directory and
    return the results.
    """
    self.hash_files = {}
    for filename in glob.glob(f'{self.target_dir}*_*'):
      _hash = filename.split('_')[1]
      if _hash not in self.hash_files:
        self.hash_files[_hash] = [filename]
      else:
        self.hash_files[_hash].append(filename)

    forwarded_hashes = list(self.hash_files.keys()) # delete
    num_procs = 48
    forwarded_hashes_splitted = [[forwarded_hashes[i] for i in list(range(i, len(forwarded_hashes), num_procs))] for i in range(num_procs)]
    quot = Queue()
    processes = [Process(target=self.processHashes, args=(forwarded_hashes_splitted[i], quot)) for i in range(num_procs)]

    for i, proc in enumerate(processes):
      proc.start()

    result = [quot.get() for p in processes]

    for i, proc in enumerate(processes):
      proc.join()

    result_list = [ent for sublist in result for ent in sublist]

    return result_list

  def writeOutput(self):
    """
    Writes the comparison results to stdout
    in the specified format (e.g., awkable).
    """
    result = self.compareDir()
    if self.output_format == "json":
      for item in result:
        print(item)
    elif self.output_format == "awkable":
      for item in result:
        for i in item:
          print(i)

c = Comparer(server_names=['nginx', 'envoy'], target_dir=argv[1], output_format="awkable")
#print(c.compare(argv[2], individual=True))
c.writeOutput()
