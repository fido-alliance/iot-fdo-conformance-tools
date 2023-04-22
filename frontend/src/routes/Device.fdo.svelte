<script>
    import {addNewDevice, removeTestRun, getDeviceTestRunsList, addNewTestRun} from '../lib/DeviceTest.api'
    import {ensureUserIsLoggedIn} from '../lib/User.api'

    ensureUserIsLoggedIn()

    let selectedDeviceTestUuid = ""
    let selectedTestRunUuid = ""

    let testRunMap = {}
    let devTestInstMap = {}


    let errorMsg = ""
    const refreshDevtList = async() => {
        try {
            let entries = await getDeviceTestRunsList()

            for(let entry of entries) {
                devTestInstMap[entry.id] = entry

                if (entry.to1) {
                    for(let testRun of entry.to1) {
                        testRunMap[testRun.uuid] = testRun
                    }
                } else {
                    entry.to1 = []
                }

                if (entry.to2) {
                    for(let testRun of entry.to2) {
                        testRunMap[testRun.uuid] = testRun
                    }
                } else {
                    entry.to2 = []
                }
            }
        } catch(err) {
            errorMsg = err; // TypeError: failed to fetch
        }
    }

    const handleSelect = async(e) => {
    }

    let doTestExecuteErrorMessage = ""
    const handleNewTestRun = async(top) => {
        doTestExecuteErrorMessage = "Adding..."
        try {
            await addNewTestRun(top, selectedDeviceTestUuid)
            doTestExecuteErrorMessage = "Success"
        } catch(e) {
            doTestExecuteErrorMessage = "Error executing DO. " + e
        }

        setTimeout(() => { 
            doTestExecuteErrorMessage = ""
        }, 1250)
    }


    let fileinput
    const readAndDecodeFile = async(e) => {
        return new Promise((resolve, reject) => {
            let selectedImageReference = e.target.files[0];
            let reader = new FileReader();
            reader.readAsDataURL(selectedImageReference);
            reader.onload = (e) => {
                let resultSplit = e.target.result.split(/^.*;base64,/);

                resolve(atob(resultSplit[1]))
            };

            reader.onerror = (e) => {
                reject("Error reading file")
            }
        })
    }

    let newDeviceFileString 
    const readFile = async(e) => {
        let fileString = await readAndDecodeFile(e)
        newDeviceFileString = fileString
    }

    const handleRemoveTestRun = async(protocol, runUuid) => {
        try {
            await removeTestRun(protocol, selectedDeviceTestUuid, runUuid)
        } catch(e) {
            doTestExecuteErrorMessage = "Error removing test run. " + e
        }
    }

    const formatLeftPanelDeviceName = (entryObj) => {
        let formatedGuid = `${entryObj.guid.slice(0,6)}...${entryObj.guid.slice(-6)}`
        return `${entryObj.name} GUID(${formatedGuid})`
    }

    const getRunDate = (run) => {
        return (new Date(run.timestamp * 1000)).toLocaleString()
    }

    const getRunState = (run) => {
        if(run.completed) {
            return "Completed"
        }

        return "Running"
    }

/* ----- Handle New Device ----- */
    let newDoErrorMessage = ""
    let newDeviceName = ""
    const handleAddNewDevice = async(e) => {
        e.preventDefault()

        newDoErrorMessage = ""
        
        // DecodeB64 pem file
        try {    
            await addNewDevice(newDeviceName, newDeviceFileString)
        } catch(e) {
            newDoErrorMessage = "Error adding new Device. " + e
            return
        }

        newDoErrorMessage = "Success"
        setTimeout(() => { 
            newDoUiVisible = false
            newDoErrorMessage = ""
            newDeviceName = ""
        }, 1250)

    }

    let newDoUiVisible = false
    const handleInitiateNewDevice = (e) => {
        e.preventDefault()
        newDoUiVisible = true
        newDoErrorMessage = ""
        newDeviceName = ""
    }

    const handleCancelInitiateNewDevice = (e) => {
        e.preventDefault()
        newDoUiVisible = false
        newDoErrorMessage = ""
        newDeviceName = ""
    }
    
/* ----- Handle New Do Ends----- */


    refreshDevtList()
    setInterval(() => {
		refreshDevtList()
    }, 2000);
</script>

<section id="first" class="main">
    <header>
        <p>{errorMsg}</p>
    </header>
    
    <div class="row gtr-uniform">
        <div class="col-4 col-12-xsmall">

            <div class="row">
                <div class="col-12 col-12-xsmall">
                    <h3>Your devices</h3>

                    {#if !!doTestExecuteErrorMessage}
                        <p>{doTestExecuteErrorMessage}</p>
                    {/if}
                </div>
            </div>

            {#each Object.keys(devTestInstMap) as entryKey}
                <div class="row">
                    <div class="col-12 col-12-xsmall">
                        <input type="radio" id="rvt-radio-{devTestInstMap[entryKey].id}" on:click={handleSelect} value="{devTestInstMap[entryKey].id}" name="rvts-radio" bind:group={selectedDeviceTestUuid}>
                        <label for="rvt-radio-{devTestInstMap[entryKey].id}">{formatLeftPanelDeviceName(devTestInstMap[entryKey])}</label>

                        {#if selectedDeviceTestUuid === devTestInstMap[entryKey].id}
                        <section class="rvt-mgmt">
                            <div class="row">
                                <div class="col-6 col-12-xsmall">
                                    <h4>TO1 Test Runs</h4>
                                </div>
                                <div class="col-6 col-12-xsmall">
                                    <a href="#" on:click|preventDefault={() => {handleNewTestRun(1)}} class="button primary fit small exec">New Test Run</a>
                                </div>
                            </div>
                            {#if devTestInstMap[entryKey].to1.length > 0}
                                {#each devTestInstMap[entryKey].to1 as run}
                                <div class="row">
                                    <div class="col-12 col-12-xsmall">
                                        <input type="radio" id="trun-radio-{run.uuid}" value="{run.uuid}" name="testrun-radio" bind:group={selectedTestRunUuid}>
                                        <label for="trun-radio-{run.uuid}"><b>{getRunState(run)}</b>: {getRunDate(run)}
                                            <a href="#" on:click|preventDefault={() => handleRemoveTestRun(run.protocol, run.uuid)} value="{run.uuid}">X</a></label>
                                    </div>
                                </div>
                                {/each}
                            {/if}

                            {#if devTestInstMap[selectedDeviceTestUuid].to1.length == 0}
                                <div class="row">
                                    <div class="col-12 col-12-xsmall">
                                        <p class="rvt-info">No records found</p>
                                    </div>
                                </div>
                            {/if}

                            <div class="row">
                                <div class="col-6 col-12-xsmall">
                                    <h4>TO2 Test Runs</h4>
                                </div>
                                <div class="col-6 col-12-xsmall">
                                    <a href="#" on:click|preventDefault={() => {handleNewTestRun(2)}} class="button primary fit small exec">New Test Run</a>
                                </div>
                            </div>

                            {#if devTestInstMap[entryKey].to2.length > 0}
                                {#each devTestInstMap[entryKey].to2 as run}
                                <div class="row">
                                    <div class="col-12 col-12-xsmall">
                                        <input type="radio" id="trun-radio-{run.uuid}" value="{run.uuid}" name="testrun-radio" bind:group={selectedTestRunUuid}>
                                        <label for="trun-radio-{run.uuid}">{getRunDate(run)} <a href="#" on:click|preventDefault={() => handleRemoveTestRun(run.protocol, run.uuid)} value="{run.uuid}">X</a></label>
                                    </div>
                                </div>
                                {/each}
                            {/if}

                            {#if devTestInstMap[selectedDeviceTestUuid].to2.length == 0}
                                <div class="row">
                                    <div class="col-12 col-12-xsmall">
                                        <p class="rvt-info">No records found</p>
                                    </div>
                                </div>
                            {/if}
                        </section>
                        {/if}
                    </div>
                </div>
            {/each}

            <div class="row ">
                <div class="col-12 col-12-xsmall">
                    <h4>RV / DO Base URL</h4>
                    <p>{location.origin}</p>
                </div>
            </div>


            <div class="row paddtobbottom">
                <div class="col-12 col-12-xsmall">
                {#if !newDoUiVisible}
                    <a href="#" on:click={handleInitiateNewDevice} class="button primary">Add new device</a>
                {:else}
                    <a href="#" on:click={handleCancelInitiateNewDevice} class="button primary cancel">Cancel</a>
                {/if}
                </div>
            </div>
            
            {#if newDoUiVisible}
                <div class="row">
                    <div class="col-12 col-12-xsmall">
                        <div class="row">
                            <div class="col-12 col-12-xsmall">
                                <input type="text" name="demo-name" bind:value={newDeviceName} id="demo-name" placeholder="Device nickname">
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-12 col-12-xsmall">
                                <input type="file" name="demo-name" accept="*" on:change={(e)=>readFile(e)} bind:this={fileinput} >
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-12 col-12-xsmall">
                                <a href="#" on:click={handleAddNewDevice} class="button primary">Add</a>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-12 col-12-xsmall">
                                <p>{newDoErrorMessage}</p>
                            </div>
                        </div>
                    </div>
                </div>
            {/if}
            
        </div>


        <!-- Results pane -->
        <div class="col-8 col-12-xsmall">
            {#if selectedTestRunUuid !== ""}
               <h3>TO{testRunMap[selectedTestRunUuid].protocol} test results</h3>
               <h4> Status: <b>{getRunState(testRunMap[selectedTestRunUuid])}</b>
                    <br>Device nickname: <b>{devTestInstMap[selectedDeviceTestUuid].name}</b> 
                    <br>Guid: <b>{devTestInstMap[selectedDeviceTestUuid].guid}</b> 
                    <br>Date: {getRunDate(testRunMap[selectedTestRunUuid])}</h4>

                {#if testRunMap[selectedTestRunUuid].tests.length > 0}
                    {#each testRunMap[selectedTestRunUuid].tests as devtest}
                        <div class="row rvt-test-case">
                
                            <div class="col-9 col-12-xsmall">
                                <p>{devtest.testId}</p>
                            </div>
                            <div class="col-3 col-12-xsmall">
                                {#if devtest.passed}
                                    <p class="success">Passed</p>
                                {:else}
                                    <p class="failed">Failed</p>
                                {/if}
                            </div>
                            <div class="col-12 col-12-xsmall">
                                <p><b>{devtest.error}</b></p>
                            </div>
                        </div>
                    {/each}
                {:else}
                    <div class="row">
                        <div class="col-12 col-12-xsmall">
                            <p>No tests executed yet</p>
                        </div>
                    </div>
                {/if}
            {:else}
                <h2>Tests info</h2>

                <div class="row">
                    <div class="col-12 col-12-xsmall">
                        <p>Test case was not selected</p>
                    </div>
                </div>
            {/if}
        </div>
    </div>
</section>