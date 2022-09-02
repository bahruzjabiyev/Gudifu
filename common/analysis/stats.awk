
function ignorable(action) {
 split(action,arr,"----")
 left=substr(arr[1],3)
 right=substr(arr[2], 1, length(arr[2])-1)
 sub(": ", ":", right)
 if (right == left) {
   return 1
 }
 return 0
}

BEGIN {FS="[ ][:]{5}[ ]"}

# The block below will be run for all the lines in the input file
{
  action_type=$1
  hash=$2
  server=$3
  action=$4
  if (action_type=="modifications" && ignorable(action)) {
  } else {
    lines[hash][$0] = ""
    #action_freqs[action_type][action]=action_freqs[action_type][action]","hash
    if (server == "nginx"){
      nginx_actions[action_type][action] = ""
      nginx_hashes[hash] = ""
      if (hash in envoy_hashes) {
        common_hashes[hash]=""
      }
    }
    else if (server == "envoy"){
      envoy_actions[action_type][action] = ""
      envoy_hashes[hash] = ""
      if (hash in nginx_hashes) {
        common_hashes[hash]=""
      }
    }
  }
}

# The block below is executed once the processing of all lines are finished.
END {

  for (hash in common_hashes) {
    for (line in lines[hash]) {
      if (op) {
	if (diff=="true") {
	  split(line,arr,"[ ][:]{5}[ ]")
	  #print arr[4]
	  if (arr[3] == "nginx" && !(arr[4] in envoy_actions[op])) {
  	    if (match(line, op)){ #&& !(ignorable(arr[4]))) {
              print line
            }
	  }
	  else if (arr[3] == "envoy" && !(arr[4] in nginx_actions[op])) {
  	    if (match(line, op)){ # && !(ignorable(arr[4]))) {
              print line
            }
	  }
	}
	else {
  	  if (match(line, op)) {
            print line
          }
        }
      }
      else {
        print line
      }
    }
  }

}
