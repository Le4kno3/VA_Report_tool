
import csv, openpyxl, re
path = "vuln-file.xlsx"

theFile = openpyxl.load_workbook(path)



# print(theFile.sheetnames)
currentSheet = theFile['Critical,High&Medium']
# print(currentSheet['B'].value)

def get_KB_article(app_version, row):

    column = "S"
    cell_name = "{}{}".format(column, row)
    cell_val = currentSheet[cell_name].value

    if(cell_val == None or cell_val == ''):
        return "N/A"

    # handle app_version * space
    if(app_version == "Microsoft SharePoint Foundation 2013"):
        pass
    else:
        app_version = "* " + app_version

    cell_val = cell_val.replace("_x000D_","")
    cell_val = cell_val.replace("\n", "")

    # print("App Version : " + app_version)
    # print("cell_value : " + cell_val)
    # print("\n")

    iter = [i for i in range(len(cell_val)) if cell_val.startswith(app_version, i)]

    # print(iter)

    kb = set()

    if iter == None or len(iter) < 1:
        return "Wrong app version"

    for i in range(0,len(iter)):
        index = iter[i]
        while True:
            if (cell_val[index] == "("):
                # print("Start Index : "+str(index))
                # print(cell_val[index:])
                distance = cell_val[index:].find(")")
                # print("End Index : " + str(index+distance))
                # print("KB = "+ cell_val[index+1:index+distance] + "\n\n")
                kb.add(cell_val[index+1:index+distance])
                break
            else:
                index = index + 1
    # print(kb)
    tmp = ', '.join(kb)
    return tmp

def get_KB_article_os(app_version, row):

    column = "S"
    cell_name = "{}{}".format(column, row)
    cell_val = currentSheet[cell_name].value

    if (cell_val == None or cell_val == ''):
        return "N/A"

    cell_val = cell_val.replace("_x000D_","")
    cell_val = cell_val.replace("\n", "")

    if ("Microsoft has removed this patch" in cell_val):
        return "Microsoft has removed this patch"

    # print("App Version : " + app_version)
    # print("cell_value : " + cell_val)
    # print("\n")

    iter = [i for i in range(len(cell_val)) if cell_val.startswith(app_version, i)]

    # print(iter)

    kb = set()

    if iter == None or len(iter) < 1:
        return "Wrong app version"

    for i in range(0,len(iter)):
        index = iter[i]
        while (cell_val[index:index + 3]) != "(KB":
            index = index + 1

        distance = cell_val[index:].find(")")

        kb.add(cell_val[index+1:index+distance])

    tmp = ', '.join(kb)
    # tmp=0
    return tmp



def handle_type1(): #completed
    for row in range(2, currentSheet.max_row + 1):

        column = "S"
        cell_name = "{}{}".format(column, row)
        val = currentSheet[cell_name].value

        # Handle missing Values in column S then output = N/A
        if val == None:
            cell_name = "{}{}".format("V", row)
            currentSheet[cell_name] = "N/A"
            continue
        cell_name = "{}{}".format("V",row)
        val = val.split("_x000D_")

        if val[0] == "Upgrade to the latest version of Oracle Java":
            currentSheet[cell_name] = "Download and apply the upgrade from:  https://www.java.com/en/download/manual.jsp"


def handle_type2():
    for row in range(2, currentSheet.max_row + 1):

        column = "T"
        cell_name = "{}{}".format(column, row)
        val = currentSheet[cell_name].value

        # Handle missing Values in column T then output = N/A
        if val == None:
            cell_name = "{}{}".format("V", row)
            currentSheet[cell_name] = "N/A"
            continue

        cell_name = "{}{}".format("V", row)
        val = val.split("_x000D_")


        # Handles : OFFICE, SHAREPOINT, SKYPE
        if val[0].find("Office") == -1 and val[0].find("SharePoint") == -1 and val[0].find("Skype") == -1:
            pass
        else:
            if ( val[0].find("Office") > -1 ):
                index = val[0].find("Office")
            elif (val[0].find("SharePoint") > -1):
                index = val[0].find("SharePoint")
            elif (val[0].find("Skype") > -1):
                index = val[0].find("Skype")


            if (len(val[0][index:]) == 11 ):
                cell_name = "{}{}".format("V", row)
                app_version =  "Microsoft " + val[0][index:]
                currentSheet[cell_name] = get_KB_article(app_version, row)
            else:
                cell_name = "{}{}".format("V", row)
                tmp = val[0].rsplit(' ', 1)[0]
                if(tmp.find(":") == -1):
                    app_version = tmp
                    currentSheet[cell_name] = get_KB_article(app_version, row)
                else:
                    index2 = tmp.find(":") + 2  # Removes "Vulnerable software installed"
                    app_version = tmp[index2:]
                    currentSheet[cell_name] = get_KB_article(app_version, row)

        # Handles : EXCHANGE
        if val[0].find("Exchange") > -1:

            index = val[0].find("Exchange")

            cell_name = "{}{}".format("V", row)
            tmp = val[0]
            if(tmp.find(":") > -1):
                index2 = tmp.find(":") + 2  # Removes "Vulnerable software installed"
                app_version = tmp[index2:]
                currentSheet[cell_name] = get_KB_article(app_version, row)

def handle_type4():
    for row in range(2, currentSheet.max_row + 1):

        column = "T"
        cell_name = "{}{}".format(column, row)
        val = currentSheet[cell_name].value

        # Handle missing Values in column T then output = N/A
        if val == None:
            cell_name = "{}{}".format("V", row)
            currentSheet[cell_name] = "N/A"
            continue

        cell_name = "{}{}".format("V", row)
        val = val.split("_x000D_")


        # Handles : ALL VULNERABLE OS: WINDOWS
        if val[0].find("Vulnerable OS: Microsoft Windows") == -1:
            pass
        else:
            # print("Triggered!")
            cell_name = "{}{}".format("V", row)
            # print(val[0])
            index = val[0].find(":") + 2
            app_version = val[0][index:]
            # print(app_version)
            # currentSheet[cell_name] = app_version
            # print(currentSheet[cell_name])

            currentSheet[cell_name] = get_KB_article_os(app_version, row)

def handle_type5(): #Rapid7 ciphers
    for row in range(2, currentSheet.max_row + 1):

        column = "S"
        cell_name = "{}{}".format(column, row)
        val = currentSheet[cell_name].value

        # Handle missing Values in column S then output = N/A
        if val == None:
            cell_name = "{}{}".format("V", row)
            currentSheet[cell_name] = "N/A"
            continue
        cell_name = "{}{}".format("V",row)
        val = val.split("_x000D_")

        if val[0] == "Disable TLS/SSL support for 3DES cipher suite":
            currentSheet[cell_name] = '''Disable TLS/SSL support for 3DES cipher suite


Configure the server to disable support for 3DES suite.

For Microsoft IIS web servers, see Microsoft Knowledgebase article  245030 (http://support.microsoft.com/kb/245030/)  for instructions on disabling 3DES cipher suite. 

The following recommended configuration provides a higher level of security. This configuration is compatible with Firefox 27, Chrome 22, IE 11, Opera 14 and Safari 7. SSLv2, SSLv3, and TLSv1 protocols are not recommended in this configuration. Instead, use TLSv1.1 and TLSv1.2 protocols.

Refer to your server vendor documentation to apply the recommended cipher configuration:

ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK
'''


    for row in range(2, currentSheet.max_row + 1):

        column = "S"
        cell_name = "{}{}".format(column, row)
        val = currentSheet[cell_name].value

        # Handle missing Values in column S then output = N/A
        if val == None:
            cell_name = "{}{}".format("V", row)
            currentSheet[cell_name] = "N/A"
            continue
        cell_name = "{}{}".format("V",row)
        val = val.split("_x000D_")

        if val[0] == "Disable TLS/SSL support for RC4 ciphers":
            currentSheet[cell_name] = '''Disable TLS/SSL support for RC4 ciphers


Configure the server to disable support for RC4 ciphers.

For Microsoft IIS web servers, see Microsoft Knowledgebase article  245030 (http://support.microsoft.com/kb/245030/)  for instructions on disabling rc4 ciphers. 

The following recommended configuration provides a higher level of security. This configuration is compatible with Firefox 27, Chrome 22, IE 11, Opera 14 and Safari 7. SSLv2, SSLv3, and TLSv1 protocols are not recommended in this configuration. Instead, use TLSv1.1 and TLSv1.2 protocols.

Refer to your server vendor documentation to apply the recommended cipher configuration:

ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK
'''


    for row in range(2, currentSheet.max_row + 1):

        column = "S"
        cell_name = "{}{}".format(column, row)
        val = currentSheet[cell_name].value

        # Handle missing Values in column S then output = N/A
        if val == None:
            cell_name = "{}{}".format("V", row)
            currentSheet[cell_name] = "N/A"
            continue
        cell_name = "{}{}".format("V",row)
        val = val.split("_x000D_")

        if val[0] == "* Apache HTTPD":
            currentSheet[cell_name] = '''* Apache HTTPD
      Disable HTTP DELETE Method for Apache

      
      Disable the DELETE method by including the following in the Apache configuration:

       <Limit DELETE> Order deny,allow Deny from all </Limit>



 * Java System Web Server, SunONE WebServer, Sun-ONE-Web-Server, iPlanet
      Disable HTTP DELETE Method for Sun Java System Web Server (or Sun ONE Web Server, iPlanet Web Server, Netscape Enterprise Server)

      
      In the server.xml configuration file, add the following lines to restrict the DELETE method to a particular user(s):

      acl "uri=/dir/*"; deny(all) user="anyone"; allow(read,list,execute,info) user="all"; allow (read,list,execute,info,write,delete) user = "username";



 * Microsoft IIS
      Disable HTTP DELETE Method for IIS

      
      Disable the DELETE method by doing the following in the IIS manager

    *  Select relevent site

    * Select Request filtering and change to HTTP verb tab

    * Select Deny Verb from the actions pane

    * Type DELETE into the provided text box and press OK



 * nginx nginx
      Disable HTTP DELETE Method for nginx

      
      Disable the DELETE method by adding the following line to your server block in your config file, you can add other HTTP methods to be allowed to run after POST

      limit_except GET POST { deny all; }



 * Disable HTTP DELETE method
      
      Disable HTTP DELETE method on your web server. Refer to your web server's instruction manual on how to do this.


      
      Web servers that respond to the DELETE HTTP method expose what other methods are supported by the web server, allowing attackers to narrow and intensify their efforts.
'''


def handle_type6():

    target_list = {}
    target_path = {}

    for row in range(2, currentSheet.max_row + 1):

        column = "A"
        cell_name = "{}{}".format(column, row)
        val1 = currentSheet[cell_name].value

        column = "N"
        cell_name = "{}{}".format(column, row)
        val2 = currentSheet[cell_name].value


        # target_list[val] =

        # Handle missing Values in column T then output = N/A
        # if val[1] == None:
        #     cell_name = "{}{}".format("V", row)
        #     currentSheet[cell_name] = "N/A"
        #     continue

        cell_name = "{}{}".format("V", row)
        val = val2.split('_x000D_\n')

        try:
            # print(val[3])
            tmp = val[3].split('(')

            tmp2 = tmp[0]
            start_i = tmp2.find("JRE") + 3
            end_i = start_i + 12

            if target_list[val1] is not None:
                if tmp2[start_i:end_i] > target_list[val1]:
                    print(tmp2[start_i:end_i] + " is greater than " + target_list[val1])
                    target_list[val1] = tmp2[start_i:end_i]
                    target_path[val1] = tmp[1][:-1]
                else:
                    pass
            else:
                target_list[val1] = tmp2[start_i:end_i]
                target_path[val1] = tmp[1][:-1]

        except:
            pass



print("Current sheet name is {}" .format(currentSheet))
# currentSheet = sheet

# This ordering is very important first 1,2,3,4

handle_type2()
# handle_type3()
handle_type4()
handle_type1()
handle_type5()
# handle_type6()          # JRE type

theFile.save("output.xlsx")