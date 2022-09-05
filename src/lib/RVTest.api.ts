
export const getRVTsListTo0 = async (): Promise<Array<any>> => {
    let result = await fetch("/api/rvt/list/to0", {
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

export const getRVTsListTo1 = async (): Promise<Array<any>> => {
    let result = await fetch("/api/rvt/list/to1", {
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
