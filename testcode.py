file = "/etc/passwd"
##for file in files_to_check:
command = "FILE=" + file + "\n"
with open("script.sh", "w") as f:
     f.write("#!/bin/bash\n")
     f.write(command)
     f.write("if [ -w $FILE ]; then\n")
     f.write('\techo "$FILE is writeable"\n')
     f.write('else\n')
     f.write("\techo "$FILE is not writeable"\n')
     f.write("fi")
