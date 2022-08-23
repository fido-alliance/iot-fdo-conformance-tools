<script>
    import {getRVTsList, addNewRv, executeRvTests} from '../lib/RVTest.api'
    import {ensureUserIsLoggedIn} from '../lib/User.api'

    ensureUserIsLoggedIn()

    let rvtListDir = {}
    let selectedRVT = ""

    let rvtTestRunDir = {}
    let selectedTestRunUuid = ""

    let errorMsg = ""
    const refreshRvtList = async() => {
        try {
            let rvtList = await getRVTsList()

            rvtListDir = {}
            rvtTestRunDir = {}
            for(let rvt of rvtList) {
                rvtListDir[rvt.id] = rvt
                
                for(let trun of rvt.runs) {
                    rvtTestRunDir[trun.uuid] = trun
                }
            }
        } catch(err) {
            errorMsg = err; // TypeError: failed to fetch
        }
    }

    const handleSelect = async(e) => {
        
        
    }

    let rvTestExecuteErrorMessage = ""
    const handleRvTestExecute = async(e) => {
        e.preventDefault()

        rvTestExecuteErrorMessage = "Executing..."
        try {
            await executeRvTests(selectedRVT)
            rvTestExecuteErrorMessage = "Success"
        } catch(e) {
            rvTestExecuteErrorMessage = "Error executing RV. " + e
        }

        setTimeout(() => { 
            rvTestExecuteErrorMessage = ""
        }, 1250)
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
            {#each Object.keys(rvtListDir) as rvtk}
                <div class="row">
                    <div class="col-12 col-12-xsmall">
                        <input type="radio" id="rvt-radio-{rvtListDir[rvtk].id}" on:click={handleSelect} value="{rvtListDir[rvtk].id}" name="rvts-radio" bind:group={selectedRVT}>
                        <label for="rvt-radio-{rvtListDir[rvtk].id}">{rvtListDir[rvtk].url}</label>

                        {#if selectedRVT === rvtListDir[rvtk].id}
                        <section class="rvt-mgmt">
                            <div class="row paddtobbottom">
                                <div class="col-12 col-12-xsmall">
                                    <a href="#" on:click={handleRvTestExecute} class="button primary fit small exec">Execute</a>
                                </div>
                                <div class="col-12 col-12-xsmall">
                                    <p class="rvt-info">{rvTestExecuteErrorMessage}</p>
                                </div>
                            </div>
                            {#if rvtListDir[rvtk].runs.length > 0}
                                {#each rvtListDir[rvtk].runs as run}
                                <div class="row">
                                    <div class="col-12 col-12-xsmall">
                                        <input type="radio" id="trun-radio-{run.uuid}" value="{run.uuid}" name="testrun-radio" bind:group={selectedTestRunUuid}>
                                        <label for="trun-radio-{run.uuid}">{(new Date(run.timestamp * 1000)).toLocaleString()}</label>
                                    </div>
                                </div>
                                {/each}
                            {:else}
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
                <h2>Tests info for {rvtListDir[selectedRVT].url} at {(new Date(rvtTestRunDir[selectedTestRunUuid].timestamp * 1000)).toLocaleString()}</h2>

                {#each Object.keys(rvtTestRunDir[selectedTestRunUuid].tests) as rvtest}
                
                <div class="row rvt-test-case">
        
                    <div class="col-9 col-12-xsmall">
                        <p>{rvtest}</p>
                    </div>
                    <div class="col-3 col-12-xsmall">
                        {#if rvtTestRunDir[selectedTestRunUuid].tests[rvtest].passed}
                            <p class="success">Passed</p>
                        {:else}
                            <p class="failed">Failed</p>
                        {/if}
                    </div>
                    <div class="col-12 col-12-xsmall">
                        <p><b>{rvtTestRunDir[selectedTestRunUuid].tests[rvtest].error}</b></p>
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