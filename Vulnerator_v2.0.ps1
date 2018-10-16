<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
function Invoke-ACASParseNetworkScore{
    Param
    (
        # Path to XLSX file we want to Vulnerate
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$false)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        $Path,

        # Ignore Low findings. Default: True
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [bool]$IgnoreLow = $true
    )

    #Import Necessary Modules

    #Only import the module if it is not already loaded
    if(-not (Get-Module -Name PSExcel)){
        Import-Module -Name ".\Modules\PSExcel\PSExcel.psm1"
    }

    #Input path to the scan report we want to process
    # $Path variable should be an object when we're passed it by the parent function
    $Path_Object = $Path
    $Path_Split = ($Path_Object.BaseName -split "_")

 

    $Network = $Path_Split[0]
    $Vendor = $Path_Split[1]
    $MachineType = ($Path_Split[2] -split "-")[0]
    $ScanDate = ($Path_Split[2] -split "-")[1]

    # Script start time
    #Starting time from when we first load the file
    #$ScriptStart = (Get-Date)    

    #Apparently you can just get the sheets by name and you don't need to get the index first
    #$Excel = New-Excel -Path $Path
    #Get the Index of the Findings tab incase it's ever moved from I3
    #$Workbook = $Excel | Get-Workbook
    #$ExecutiveReportIndex = ($Workbook | Get-Worksheet -Name ).Index
    #$FindingsIndex = ($Workbook | Get-Worksheet -Name ).Index

    # Import the executive tab into an object. Supress the Warnings since these files had crappy headers
    $ExecutiveReportData = Import-XLSX -Path $Path_Object.FullName -Sheet 'Executive_Report' -WarningAction SilentlyContinue
    $TotalScanned = $ExecutiveReportData[0]."<Column 2>"

    # Import the findings tab into an object. Supress the Warnings since these files had crappy headers
    $Findings_Object = Import-XLSX -Path $Path_Object.FullName -Sheet 'Findings' -WarningAction SilentlyContinue

    #Get Unique Plugins

    if($IgnoreLow){
        $UniquePlugins_Object = $Findings_Object | Where-Object { $_."Severity" -ne "Low"} | Select-Object -Property "Plugin" -Unique
    }else{
        $UniquePlugins_Object = $Findings_Object | Select-Object -Property "Plugin" -Unique
    }

    #Inefficent Way
    #$OutputObject = @()

    #Efficient Way
    $OutputObject = [System.Collections.ArrayList]::new()


    #Generate Score Impact Per Finding
    $i = 0
    foreach($Plugin in $UniquePlugins_Object){

        #Inefficient
        #$Data_Plugin_Object = $Findings_Object | Where-Object {$_.Plugin -eq $Plugin.Plugin}

        #Efficient
        $Count = 0
        foreach($Finding in $Findings_Object){
            if($Finding.Plugin -eq $Plugin.Plugin){
                if($Count -eq 0){
                    $PluginName = $Finding."Plugin Name"
                    $Severity = $Finding."Severity"
                    $Solution = $Finding."Solution"
                    $PluginPublicationDate = [DateTime]::FromOADate($Finding."Plugin Publication Date")
                    $DueDate = $PluginPublicationDate.AddDays(21)
                }
                $Count = $Count + 1
            }
        }

        #Inefficient
        <#
        $PluginName = $Data_Plugin_Object[0]."Plugin Name"
        $Severity = $Data_Plugin_Object[0]."Severity"
        $Solution = $Data_Plugin_Object[0]."Solution"
        $PluginPublicationDate = [DateTime]::FromOADate(($Data_Plugin_Object."Plugin Publication Date")[0])
        $DueDate = $PluginPublicationDate.AddDays(21)
        $Count = $Data_Plugin_Object.Count
        #>

        if($Severity -eq "Critical" -or $Severity -eq "High"){
            $ScoreImpact = ((10/15) * $Count/$TotalScanned)
        }elseif($Severity -eq "Medium"){
            $ScoreImpact = ((4/15) * $Count/$TotalScanned)
        }elseif($Severity -eq "Low"){
            #TODO Low Score Impact Calculation
            $ScoreImpact = ((1/15) * $Count/$TotalScanned)
        }else{
            Write-Error "Severity not defined!"
        }

        <#
        $PluginOutputObject = New-Object -TypeName psobject
        $PluginOutputObject | Add-Member -MemberType NoteProperty -Name "Network" -Value $Network
        $PluginOutputObject | Add-Member -MemberType NoteProperty -Name "Vendor" -Value $Vendor
        $PluginOutputObject | Add-Member -MemberType NoteProperty -Name "Machine Type" -Value $MachineType
        $PluginOutputObject | Add-Member -MemberType NoteProperty -Name "ScoreImpact" -Value $ScoreImpact
        $PluginOutputObject | Add-Member -MemberType NoteProperty -Name "Plugin" -Value $Plugin.Plugin
        $PluginOutputObject | Add-Member -MemberType NoteProperty -Name "Plugin Name" -Value $PluginName
        $PluginOutputObject | Add-Member -MemberType NoteProperty -Name "Severity" -Value $Severity
        $PluginOutputObject | Add-Member -MemberType NoteProperty -Name "Solution" -Value $Solution
        $PluginOutputObject | Add-Member -MemberType NoteProperty -Name "Plugin Publication Date" -Value $PluginPublicationDate
        $PluginOutputObject | Add-Member -MemberType NoteProperty -Name "Due Date" -Value $DueDate
        $PluginOutputObject | Add-Member -MemberType NoteProperty -Name "Count" -Value $Count
        #>

        #Optimized Method
        $PluginOutputObject = [pscustomobject]@{
            "Network" = $Network
            "Vendor" = $Vendor
            "Machine Type" = $MachineType
            "ScoreImpact" = $ScoreImpact
            "Plugin" = $Plugin.Plugin
            "Plugin Name" = $PluginName
            "Severity" = $Severity
            "Solution" = $Solution
            "Plugin Publication Date" = $PluginPublicationDate
            "Due Date" = $DueDate
            "Count" = $Count
        }

        #You have to cast this line to void or output it to void otherwise it will output the index to the console
        [void]$OutputObject.Add($PluginOutputObject)

        $i +=1
        Write-Progress -Activity "Vulnerating" -Status "Processing Plugin $($Plugin.Plugin)" -PercentComplete (($i/$UniquePlugins_Object.Count)*100)
    }


    #Check if the rollup already exists. If it does append to it. If not just write the file normally
    $OutputPath = "$($Path_Object.Directory)\$($ScanDate)-PastDue-vulnerabilityrollup.xlsx"

    if(Test-Path $OutputPath){
        $OutputObject | Export-XLSX -Path $OutputPath -Append
    }else{
        $OutputObject | Export-XLSX -Path $OutputPath
    }
    

    # Script end time
    #$ScriptEnd = (Get-Date)

    # Time elapsed processing script
    #Write-Verbose "Elapsed Time Processing $($Path_Object.BaseName): $(($ScriptEnd-$ScriptStart).totalseconds) seconds"
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Invoke-ACASVulnerator -Path "C:\Temp\Week25Scans\"
.EXAMPLE
    Run Vulnerator against all scans in a specific folder ignoring specific scans by title
   Invoke-ACASVulnerator -Path "C:\Temp\Week25Scans\" -UnwantedScans @("DC","Server","Linux")
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
function Invoke-ACASVulnerator{
    Param
    (
        # Path to XLSX files we want to Vulnerate
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        $Path,

        # ArrayList of unwanted scans to exclude from processing
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Array]$UnwantedScans
    )

    #Initilize Variables
    #$Path = "C:\Users\KingLinkTiger\Documents\Work\Vulnerator\Test Data\"

    #Built in Unwatned Scans
    $UnwantedScans += "vulnerabilityrollup"

    $XLSXFiles = Get-ChildItem -Path $Path -Filter "*.xlsx"

    foreach($XLSX in $XLSXFiles){

        # By Default We want every file
        $Wanted = $true

        foreach($UnwantedScan in $UnwantedScans){
            if($XLSX.BaseName -match $UnwantedScan){
                $Wanted = $false
            }
        }

        #If we do not want this file skip it and continue the loop
        if(-not $Wanted){
            continue
        }

        #For All Wanted Scans do the following
        Write-Verbose "Processing File: $($XLSX.BaseName)"

        #Sneaky Measure-Command instead of Start and Stop Time :)
        (Measure-Command {
            Invoke-ACASParseNetworkScore -Path $XLSX
        }).TotalSeconds
    }
}


#NOTE THE FOLLOWING ARE NOT COMPLETED OR WOKRING FUNCTIONS

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Invoke-ACASVulnerator -Path "C:\Temp\Week25Scans\"
.EXAMPLE
    Run Vulnerator against all scans in a specific folder ignoring specific scans by title
   Invoke-ACASVulnerator -Path "C:\Temp\Week25Scans\" -UnwantedScans @("DC","Server","Linux")
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
function Invoke-ACASParser{
    Param
    (
        # Path to XLSX files we want to Vulnerate
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        $Path,

        # ArrayList of unwanted scans to exclude from processing
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Array]$UnwantedScans,

        # ArrayList wanted system types
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Server", "Workstation", "DC")]
        [Array]$SystemTypes,

        # ArrayList of wanted NetBIOSNames
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [Array]$NetBIOSNames,

        # ArrayList of wanted DNSName
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [Array]$DNSNames
    )

    #Built in Unwatned Scans
    #We never want the rollup
    $UnwantedScans += "vulnerabilityrollup"

    $XLSXFiles = Get-ChildItem -Path $Path -Filter "*.xlsx"

    foreach($XLSX in $XLSXFiles){

        # By Default We want every file
        $Wanted = $false

        #Go though each unwanted scan and mark it as not wanted
        if($UnwantedScans -ne $null){
            foreach($UnwantedScan in $UnwantedScans){
                if($XLSX.BaseName -match $UnwantedScan){
                    $Wanted = $false
                }
            }
        }

        #Then go through each wanted system type scan and set it to wanted, incase we set it to unwanted.
        if($SystemTypes -ne $null){
            foreach($SystemType in $SystemTypes){
                if($XLSX.BaseName -match $SystemType){
                    $Wanted = $true
                }
            }
        }


        #If we do not want this file skip it and continue the loop
        if(-not $Wanted){
            continue
        }

        #For All Wanted Scans do the following
        Write-Verbose "Processing File: $($XLSX.BaseName)"

        #Sneaky Measure-Command instead of Start and Stop Time :)
        (Measure-Command {
            Invoke-ACASParserWorker -Path $XLSX -NetBIOSNames $NetBIOSNames -DNSNames $DNSNames
        }).TotalSeconds
    }
}


<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
function Invoke-ACASParserWorker{
    Param
    (
        # Path to XLSX file we want to Vulnerate
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$false)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        $Path,

        # ArrayList of wanted NetBIOSNames
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [Array]$NetBIOSNames,

        # ArrayList of wanted DNSName
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [Array]$DNSNames
    )

    #Import Necessary Modules

    #Only import the module if it is not already loaded
    if(-not (Get-Module -Name PSExcel)){
        Import-Module -Name ".\Modules\PSExcel\PSExcel.psm1"
    }

    <#
        Default our search index to by NetBIOS Name
        0 = Both
        1 = NetBIOS
        2 = DNSName
    #>
    $SearchTypeIndex = 1

    if($DNSNames -ne $null -and $NetBIOSNames -ne $null){
        $SearchTypeIndex = 0
    }elseif($DNSNames -ne $null -and $NetBIOSNames -eq $null){
        $SearchTypeIndex = 2
    }
    

    #Input path to the scan report we want to process
    # $Path variable should be an object when we're passed it by the parent function
    $Path_Object = $Path
    $Path_Split = ($Path_Object.BaseName -split "_")


    $Network = $Path_Split[0]
    $Vendor = $Path_Split[1]
    $MachineType = ($Path_Split[2] -split "-")[0]
    $ScanDate = ($Path_Split[2] -split "-")[1]


    # Import the executive tab into an object. Supress the Warnings since these files had crappy headers
    $ExecutiveReportData = Import-XLSX -Path $Path_Object.FullName -Sheet 'Executive_Report' -WarningAction SilentlyContinue
    $TotalScanned = $ExecutiveReportData[0]."<Column 2>"

    # Import the findings tab into an object. Supress the Warnings since these files had crappy headers
    $Findings_Object = Import-XLSX -Path $Path_Object.FullName -Sheet 'Findings' -WarningAction SilentlyContinue


    #Efficient Way
    $OutputObject = [System.Collections.ArrayList]::new()

    foreach($Finding in $Findings_Object){
        $Wanted = $false

        switch($SearchTypeIndex){
            0{

            }
            1{
                if($NetBIOSNames -contains $Finding."NetBIOS Name"){
                    $Wanted = $true
                }
                <#
                foreach($NetBIOSName in $NetBIOSNames){
                    if($Finding."NetBIOS Name" -eq $NetBIOSName){
                        $Wanted = $true
                    }
                }
                #>
            }
            2{

            }
        }

        #If this finding is not wanted continue the loop
        if(-not $Wanted){
            continue
        }

        #Otherwise assume this finding is wanted and add it to the output
        [void]$OutputObject.Add($Finding)
    }

    $OutputPath = "$($Path_Object.Directory)\$($ScanDate)-CustomReport.xlsx"

    if(Test-Path $OutputPath){
        $OutputObject | Export-XLSX -Path $OutputPath -Append
    }else{
        $OutputObject | Export-XLSX -Path $OutputPath
    }


    #Build new Executive Report
    #Calculate a new Total Scanned. This will be hard since we don't know of any systems that DON'T have any vulnerabilities. We only know of the ones that do.
    $TotalScanned

}