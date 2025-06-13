#https://automation.trendmicro.com/xdr/api-v3/#tag/Search/paths/~1v3.0~1search~1emailActivities/get
#v1.2 Changed initial query on findEmailFirstQuery() from $oneDay till $today   to   $sevenDaysAgo till $today
$auditorApi = $env:auditorApi
Write-Host "Phishing Hunter v1.34 - module imported - PB" -ForegroundColor Gray 

#-------- STATIC VARIABLES
$emailActivityUrl = "https://api.eu.xdr.trendmicro.com/v3.0/search/emailActivities" #Email Activity Endpoint
$yourPhishingReportingEmail = "" #Change this to your Phishing reporting email users are sending phishing email to


#------------------------------------------------------ GLOBAL VARIABLE ENDS

#SUB FUNCTIONS START    ------------------------------------
function Get-CustomDate {
    param (
        [DateTime]$DateTime = (Get-Date).ToUniversalTime()
    )

    return $DateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
} #used to convert time for Trend VisionOne query
function convertTimeToFriendly($abuseIpDbTime){
# Convert to DateTime object
$datetime = [datetime]::Parse($abuseIpDbTime)

# Format as dd-MMM-yyyy
$formattedDate = $datetime.ToString("dd-MMM-yyyy")

# Output
$formattedDate


} #used on getAbuseIpDbReport
#SUB FUNCTIONS END      ------------------------------------
##################################################
##################################################
##################################################

#--------------------------------------------- - GLOBAL VARIABLES


$now          = Get-CustomDate -DateTime (get-date).AddMinutes(-5)
$twoHoursAgo  = Get-CustomDate -DateTime (get-date).AddHours(-2)
$oneDayAgo    = Get-CustomDate -DateTime (get-date).AddDays(-1)
$sevenDaysAgo = Get-CustomDate -DateTime (get-date).AddDays(-7)
$oneMonthAgo = Get-CustomDate -DateTime (get-date).AddDays(-30)


#Fetch Initial Data Section
#1st Get sender and subject from reported phishing email
function findEmailFirstQuery($email){
#----------------------1st Query Find the Email Reported Sender and Subject
#https://automation.trendmicro.com/xdr/api-v3/#tag/Search/paths/~1v3.0~1search~1emailActivities/get
$headers = @{
"Authorization"     = "Bearer $auditorApi"
"TMV1-Query"        = "mailFromAddresses:$email and mailToAddresses:$yourPhishingReportingEmail"
}

$queryParams = @{
    top            = "1"
    startDateTime  = "$sevenDaysAgo"
    endDateTime    = "$now"
    mode           = "default"
    select         = "mailMsgSubject,mailFromAddresses,mailToAddresses"
}

# Query parameters
$queryString = ($queryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&"


$url = $emailActivityUrl + "?" + $queryString

$res = Invoke-WebRequest -Uri $url -Method Get -Headers $headers
$res.content

$res = $res.Content | ConvertFrom-Json
$response = $res.items


$info = $response.mailMsgSubject 
Try{
    $infoX = $info.split("|")
    $infoBlob = [pscustomobject]@{
        reportedPhishing = $infoX[0]
        reportedEmail    = $infoX[1]
        reportedSubject  = $infoX[2]
}
    }#cls Try
Catch{}

return $infoBlob  
    }
#2nd Query Get Original Reported email for its header, ip, replyAddress,links etc...
function getPhishingInfoTrend($email){
Write-Host "Searching for Phishing Email reported by $email" -ForegroundColor Cyan
$infoBlob = findEmailFirstQuery -email $email
$reportedEmail   = $infoBlob.reportedEmail
$reportedSubject = $infoBlob.reportedSubject

$headers2 = @{
"Authorization"     = "Bearer $auditorApi"
"TMV1-Query"        = "mailFromAddresses:$reportedEmail and mailToAddresses:$email"
}


# Query parameters
$queryParams2 = @{
    top            = "1"
    startDateTime  = "$sevenDaysAgo"
    endDateTime    = "$now"
    mode           = "default"
    select         = "mailMsgSubject,mailSourceDomain,mailFromAddresses,mailToAddresses,mailSenderIp,mailWantedHeaderValue,mailWholeHeader,mailFolder,mailReplyToAddresses,eventName"
}

# Build the query string
$queryString2 = ($queryParams2.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&"
$url = $emailActivityUrl + "?" + $queryString2
$res = Invoke-WebRequest -Uri $url -Method Get -Headers $headers2
$res = $res.Content | ConvertFrom-Json
$response = $res.items

   $eventname               = $response.eventName
   $mailSourceDomain        = $response.mailSourceDomain
   $mailSenderIp            = $response.mailSenderIp
   $mailToAddresses         = $response.mailToAddresses
   $mailFromAddresses       = $response.mailFromAddresses
   $mailReplyToAddresses    = $response.mailReplyToAddresses
   $mailWholeHeader         = $response.mailWholeHeader
   $mailMsgSubject          = $response.mailMsgSubject
   $mailToAddresses         = $response.mainToAddresses
   $mailFolder              = $response.mailFolder
   $mailWantedHeaderValue   = $response.mailWantedHeaderValue


$blob = [pscustomobject]@{
   "eventname"               = $eventName
   "mailSourceDomain"        = $mailSourceDomain
   "mailSenderIp"            = $mailSenderIp
   "mailReplyToAddresses"    = $mailReplyToAddresses
   "mailFromAddresses"       = $mailFromAddresses
   "mailWholeHeader"         = $mailWholeHeader
   "mailMsgSubject"          = $mailMsgSubject
   "mailToAddresses"         = $mailToAddresses
   "mailFolder"              = $mailFolder
   "mailWantedHeaderValue"   = $mailWantedHeaderValue
   "reportedEmail"           = $reportedEmail
   "reportedSubject"         = $reportedSubject
}
#Write-Host $blob -ForegroundColor Cyan #debug only
return $blob
}



## = Sub Functions of Final Phish --------------
function checkFalsePositive($email) {
    $responseDictionary = @{
    "DoNotReply@uk.tmcas.trendmicro.com" = "[FALSE POSITIVE] - User reported Trend Micro TMCAS email as malicious"
    "bazzofx@outlook.com"                = "[FALSE POSITIVE] - Paulo Bazzo test email account. Please ignore"
    }
    
        if ($responseDictionary.ContainsKey($email)) {
            Write-Host "False positive detected:" -ForegroundColor Cyan
            Write-Host $responseDictionary[$email]
           return $responseDictionary[$email]
        }
        else{
        return "Unknown"
        }
    
    }
function checkHeaderStatus($header){
        $currentErrorAction = $ErrorActionPreference
        $ErrorActionPreference = "Stop"
        try{
        $header -match 'spf=(\w+)'
        $headerStatus = $spf.split(";").trim() 
        }
        Catch{}
        $ErrorActionPreference = $currentErrorAction
        return $headerStatus
        }   
## = Sub Functions ENDof Final Phish --------------        
        
#Digest Data Section Information
#--- PROCESS FUNCTIONS
#-------------- Abuse IP DB Data Fetcher ------------------------

function checkAbuseIpInfo($suspiciousIp){
$baseurl = "https://api.abuseipdb.com/api/v2/check"

$apiKey = $env:abuseipdbAPI  # Or replace with your API key as a string
$ipAddress = $suspiciousIp
$maxAge = 90
$verbose = "true"

$headers = @{
    "Key"    = $apiKey
    "Accept" = "application/json"
}


$url = "$baseurl"+"?ipAddress=$ipAddress&maxAgeInDays=$maxAge"

$response = Invoke-RestMethod -Uri $url -Headers $headers

$res = $response.data


$confidenceLevel = $res.abuseConfidenceScore
$actualDomain    = $res.domain
$isTor         = $res.isTor

$blob = [PSCustomObject]@{
"confidenceLevel" = $confidenceLevel
"actualDomain"    = $actualDomain 
"isTor"           = $isTor
}
return $blob

}
function getAbuseIpReports($suspiciousIp){
$baseurl = "https://api.abuseipdb.com/api/v2/reports"

$apiKey = $env:abuseipdbAPI
$ipAddress = $suspiciousIp #118.25.6.39 used for testing only
$maxAge = 90
$verbose = "true"

$headers = @{
    "Key"    = $apiKey
    "Accept" = "application/json"
}

try{
$url = "$baseurl"+"?ipAddress=$ipAddress&maxAgeInDays=$maxAge&page=1&perPage=5"
$response = Invoke-RestMethod -Uri $url -Headers $headers
$res = $response.data
$total = $res.total
}
Catch{}

$array = @()
if($total -le 0){

    $obj = [psCustomObject]@{
        "status"  = "Clean"
        "time"    = "n/a"
        "comment" = "n/a"
    } #psCustomObject
    $array += $obj
}

else{
#if there are reports showing the IP is malicious return arrau with information
$results = $res.results

    forEach($x in $results){
    $time = convertTimeToFriendly -abuseIpDbTime $x.reportedAt
    $comment = $x.comment

        if($comment -eq "" -or $comment -eq $null){$comment = "No comment"}#cls if
    $obj = [psCustomObject]@{
        "status"  = "Suspicious"
        "time"    = $time
        "comment" = $comment
    } #psCustomObject


    Write-Host "[IP REPORTED] $time" -ForegroundColor Yellow
    $array += $obj

        }#forEach

}

return $array

}




function Phish($email){

$banner = @"
    .---.
  (_,/\ \     
  ('a a(  )  First Impact    
  ) \=  ) (        Phishing Analysis - v1.3
  (.--' '--.)    
  / (_\_/_) \      Checking x---> $email
  | / \   / \ |      Trend +  AbuseIPDB
  \\ / . \ //         
  \/\___/\/  
  |  \_/  |         
  \  /  /   *           
   \/  /   .                
    ( (        *   
    |\ \    .           
    | | \     *             
   /_Y/_Y_______________________________ Script by P.B ~*
"@   
#Align Data Section
Write-Host $banner -ForegroundColor Cyan
$res = getPhishingInfoTrend -email $email
$ip                         = $res.mailSenderIp
$replyEmail                 = $res.mailReplyToAddresses | Select-Object -First 1
$emailSender                = $res.mailFromAddresses | Sort-Object -Unique
$wholeHeader                = $res.mailWholeHeader | Sort-Object -Unique | Select-Object -First 1
$domain                     = $res.mailSourceDomain
$header                     = $res.mailWantedHeaderValue 
$headerStatus               = checkHeaderStatus -header $header
[string]$hh                 =  $headerStatus 
    $headerStatusPieces     = $hh.split(";")
    $header0                = $headerStatusPieces[0]   
    $header1                = $headerStatusPieces[1]  
    $header3                = $headerStatusPieces[-2]
    $header4                = $headerStatusPieces[-1].split("(").replace("(","")
$abuseIPDbStatus            = if($ip -eq $null -or $ip -eq ""){"N/A"}else{getAbuseIpReports -suspiciousIp $ip}
    $status                 = $abuseIPDbStatus.status   | Select-Object -First 1
    $abuseIpComment         = $abuseIPDbStatus.comment  | Select-Object -First 1
    $abuseIpCommentTime     = $abuseIPDbStatus.time     | Select-Object -First 1
$checkAbuseIpInfo           = if($ip -eq $null -or $ip -eq ""){"N/A"}else{checkAbuseIpInfo -suspiciousIp $ip}
    $actualDomain           = $checkAbuseIpInfo.actualDomain
    $confidenceLevel        = $checkAbuseIpInfo.confidenceLevel
    $isTor                  = $checkAbuseIpInfo.isTor
$reportedEmail              = $res.reportedEmail
$reportedSubjectBlob        = $res.reportedSubject
    $reportedSubjectBlob    = $reportedSubjectBlob.split(")").trim().replace("(","")    
    $reportedSubject        = $reportedSubjectBlob[0]
    $reportedArrivalTime    = $reportedSubjectBlob[1]
$EngineerComment            = checkFalsePositive -email $reportedEmail


if(!($ip)){
    Write-Host "Reported Phishing Email not found on Trend" -ForegroundColor Yellow
    $response = [psCustomObject]@{
    "Reported Email"            = $reportedEmail
    "Reported Subject"          = $reportedSubject
    }
}
else
{
$response = [psCustomObject]@{
"Risk Score"                = "------------------"
"confidenceLevel"           = $confidenceLevel
"Email Info    "            = "------------------"
"Reported By"              = $email
"Reported Email"            = $reportedEmail
"Domain"                    = $domain
"Email Subject"             = $reportedSubject
"Email Arrival Time"        = $reportedArrivalTime
"Vision One Info"           = "------------------"
"IP"                        = $ip
"Engineer Comment"          = $EngineerComment
"Sender"                    = $emailSender 
"Reply Email"               = $replyEmail
"Whole Header"              = $wholeHeader
"SPF"                       = $header0.trim()
"DKIM"                      = $header1.trim()
"DMARC"                     = $header3.trim()
"DMARC Score"               = $header4.trim()
"Abuse IPDB Info"           = "------------------"
"abuse IPDB Status"         = $status
"Abuse IPDB Comment"        = $abuseIpComment
"Abuse IPDB timeComment"    = $abuseIpCommentTime
"Actual Domain"             = $actualDomain
"is Tor"                    = $isTor
}


}

$response
}

Export-ModuleMember -Function phish