
export const getRVTsList = async (): Promise<Array<any>> => {
    let result = await fetch("/api/rvt/list", {
        method: "GET",
        headers: {
        "Content-Type": "application/json",
        },
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        let statusText = result.statusText

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage
        }

        return Promise.reject(`Error sending request: ${statusText}`)
    }

    return resultJson.rvts
}

export const addNewRv = async (url): Promise<Array<any>> => {
    let result = await fetch("/api/rvt/create", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({url})
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        let statusText = result.statusText

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage
        }

        return Promise.reject(`Error sending request: ${statusText}`)
    }

    return resultJson.rvts
}



export const executeRvTests = async (id): Promise<Array<any>> => {
    let result = await fetch("/api/rvt/execute", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({id})
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        let statusText = result.statusText

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage
        }

        return Promise.reject(`Error sending request: ${statusText}`)
    }

    return resultJson.rvts
}

export const removeTestRun = async (id: string, testRunId: string): Promise<Array<any>> => {
    let result = await fetch("/api/rvt/list/testrun", {
        method: "DELETE",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({id, testRunId})
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        let statusText = result.statusText

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage
        }

        return Promise.reject(`Error sending request: ${statusText}`)
    }

    return resultJson.rvts
}
