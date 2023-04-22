<script>
    import {getRVTsList, removeTestRun, addNewRv, executeRvTests} from '../lib/RVTest.api'
    import {ensureUserIsLoggedIn} from '../lib/User.api'

    ensureUserIsLoggedIn()

    let selectedRVTUuid = ""
    let selectedTestRunUuid = ""

    let testRunMap = {}
    let rvtMap = {}

    let errorMsg = ""
    const refreshRvtList = async() => {
        try {
            let rvtList = await getRVTsList()

            for(let rvt of rvtList) {
                rvtMap[rvt.id] = rvt

                for(let testRun of rvt.to0.runs) {
                    testRunMap[testRun.uuid] = testRun
                }

                for(let testRun of rvt.to1.runs) {
                    testRunMap[testRun.uuid] = testRun
                }
            }

            
        } catch(err) {
            errorMsg = err; // TypeError: failed to fetch
        }
    }

    const handleSelect = async(e) => {
        

    }

    let rvTestExecuteErrorMessage = ""
    const handleRvTestExecuteTo0 = async(e) => {
        e.preventDefault()

        rvTestExecuteErrorMessage = "Executing..."
        try {
            await executeRvTests(rvtMap[selectedRVTUuid].to0.id)
            rvTestExecuteErrorMessage = "Success"
        } catch(e) {
            rvTestExecuteErrorMessage = "Error executing RV. " + e
        }

        setTimeout(() => { 
            rvTestExecuteErrorMessage = ""
        }, 1250)
    }

    const handleRvTestExecuteTo1 = async(e) => {
        e.preventDefault()

        rvTestExecuteErrorMessage = "Executing..."
        try {
            await executeRvTests(rvtMap[selectedRVTUuid].to1.id)
            rvTestExecuteErrorMessage = "Success"
        } catch(e) {
            rvTestExecuteErrorMessage = "Error executing RV. " + e
        }

        setTimeout(() => { 
            rvTestExecuteErrorMessage = ""
        }, 1250)
    }


    const handleRemoveTestRun = async(id, protocol) => {
        try {
            if(protocol == 0) {
                await removeTestRun(rvtMap[selectedRVTUuid].to0.id, id)
            } else {
                await removeTestRun(rvtMap[selectedRVTUuid].to1.id, id)
            }
        } catch(e) {
            rvTestExecuteErrorMessage = "Error removing test run. " + e
        }
    }


/* ----- Handle New RV ----- */
    let newRvErrorMessage = ""
    let newRvUrl = ""
    const handleAddNewRv = async(e) => {
        e.preventDefault()

        newRvErrorMessage = ""

        try {
            new URL(newRvUrl)
            await addNewRv(newRvUrl)
        } catch(e) {
            newRvErrorMessage = "Error adding new RV. " + e
            return
        }

        newRvErrorMessage = "Success"
        setTimeout(() => { 
            newRvUiVisible = false
            newRvErrorMessage = ""
            newRvUrl = ""
        }, 1250)

    }

    let newRvUiVisible = false
    const handleInitiateNewRv = (e) => {
        e.preventDefault()
        newRvUiVisible = true
        newRvErrorMessage = ""
        newRvUrl = ""
    }

    const handleCancelInitiateNewRv = (e) => {
        e.preventDefault()
        newRvUiVisible = false
        newRvErrorMessage = ""
        newRvUrl = ""
    }
/* ----- Handle New RV Ends----- */


    refreshRvtList()
    setInterval(() => {
		refreshRvtList()
    }, 2000);
</script>

<section id="first" class="main">
    <header>
        <p>{errorMsg}</p>
    </header>

    <div class="row gtr-uniform">
        <div class="col-4 col-12-xsmall">
            <h2>Available RVs for testing</h2>
            <!-- {selectedRVT}
            {selectedTestRunUuid} -->
            {#each Object.keys(rvtMap) as rvtk}
                <div class="row">
                    <div class="col-12 col-12-xsmall">
                        <input type="radio" id="rvt-radio-{rvtMap[rvtk].id}" on:click={handleSelect} value="{rvtMap[rvtk].id}" name="rvts-radio" bind:group={selectedRVTUuid}>
                        <label for="rvt-radio-{rvtMap[rvtk].id}">{rvtMap[rvtk].url}</label>

                        {#if selectedRVTUuid === rvtMap[rvtk].id}
                        <section class="rvt-mgmt">
                            <div class="row paddtobbottom">
                                <div class="col-6 col-12-xsmall">
                                    <a href="#" on:click|preventDefault={handleRvTestExecuteTo0} class="button primary fit small exec">Execute To0</a>
                                </div>
                                <div class="col-6 col-12-xsmall">
                                    <a href="#" on:click|preventDefault={handleRvTestExecuteTo1} class="button primary fit small exec">Execute To1</a>
                                </div>
                                <div class="col-12 col-12-xsmall">
                                    <p class="rvt-info">{rvTestExecuteErrorMessage}</p>
                                </div>
                            </div>
                            {#if rvtMap[rvtk].to0.runs.length > 0}
                                {#each rvtMap[rvtk].to0.runs as run}
                                <div class="row">
                                    <div class="col-12 col-12-xsmall">
                                        <input type="radio" id="trun-radio-{run.uuid}" value="{run.uuid}" name="testrun-radio" bind:group={selectedTestRunUuid}>
                                        <label for="trun-radio-{run.uuid}">TO{run.protocol} {(new Date(run.timestamp * 1000)).toLocaleString()} <a href="#" on:click|preventDefault={() => handleRemoveTestRun(run.uuid, run.protocol)} value="{run.uuid}">X</a></label>
                                    </div>
                                </div>
                                {/each}
                            {/if}

                            {#if rvtMap[rvtk].to1.runs.length > 0}
                                {#each rvtMap[rvtk].to1.runs as run}
                                <div class="row">
                                    <div class="col-12 col-12-xsmall">
                                        <input type="radio" id="trun-radio-{run.uuid}" value="{run.uuid}" name="testrun-radio" bind:group={selectedTestRunUuid}>
                                        <label for="trun-radio-{run.uuid}">TO{run.protocol} {(new Date(run.timestamp * 1000)).toLocaleString()} <a href="#" on:click|preventDefault={() => handleRemoveTestRun(run.uuid, run.protocol)} value="{run.uuid}">X</a></label>
                                    </div>
                                </div>
                                {/each}
                            {/if}

                            {#if rvtMap[rvtk].to0.runs.length == 0 && rvtMap[rvtk].to1.runs.length == 0}
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


            <div class="row paddtobbottom">
                <div class="col-12 col-12-xsmall">
                {#if !newRvUiVisible}
                    <a href="#" on:click={handleInitiateNewRv} class="button primary">Add new RV</a>
                {:else}
                    <a href="#" on:click={handleCancelInitiateNewRv} class="button primary cancel">Cancel</a>
                {/if}
                </div>
            </div>
            
            {#if newRvUiVisible}
                <div class="row">
                    <div class="col-8 col-12-xsmall">
                        <input type="text" name="demo-name" bind:value={newRvUrl} id="demo-name" placeholder="RV URL">
                    </div>
                    <div class="col-4 col-12-xsmall">
                        <a href="#" on:click={handleAddNewRv} class="button primary">Add</a>
                    </div>
                </div>
                <div class="row">
                    <div class="col-12 col-12-xsmall">
                        <p>{newRvErrorMessage}</p>
                    </div>
                </div>
            {/if}
            
        </div>
        <div class="col-8 col-12-xsmall">
            {#if selectedTestRunUuid !== ""}
                <h2>TO{testRunMap[selectedTestRunUuid].protocol} Tests info for {rvtMap[selectedRVTUuid].url} at {(new Date(testRunMap[selectedTestRunUuid].timestamp * 1000)).toLocaleString()}</h2>

                {#each Object.keys(testRunMap[selectedTestRunUuid].tests) as rvtest}
                
                <div class="row rvt-test-case">
        
                    <div class="col-9 col-12-xsmall">
                        <p>{rvtest}</p>
                    </div>
                    <div class="col-3 col-12-xsmall">
                        {#if testRunMap[selectedTestRunUuid].tests[rvtest].passed}
                            <p class="success">Passed</p>
                        {:else}
                            <p class="failed">Failed</p>
                        {/if}
                    </div>
                    <div class="col-12 col-12-xsmall">
                        <p><b>{testRunMap[selectedTestRunUuid].tests[rvtest].error}</b></p>
                    </div>
                </div>
                {/each}
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