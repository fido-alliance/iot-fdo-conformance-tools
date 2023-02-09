<script lang="ts">
    import svelteLogo from '../assets/FIDO_Alliance_logo_black_RGB.webp'
    import {completeOAuth2Reg, register} from '../lib/User.api'
    import {push} from "svelte-spa-router"

    let email: string = ""
    let password: string = ""
    let passwordRepeat: string = ""
    let name: string = ""
    let company: string = ""
    let phone: string = ""
    let errorMsg: string = ""

    const handleCompleOAuth2Reg = async (e) => {
        e.preventDefault()
        errorMsg = ""

        await completeOAuth2Reg(company, name, phone)
        .then(() => {
            errorMsg = "Thank you. You will be contacted by FIDO Alliance staff in few days..."
            window.setTimeout(() => push("/"), 1500)
        })
        .catch((err) => {
            errorMsg = err
        })
    }
</script>

<section id="intro" class="main">
    <div class="spotlight">
        <div class="content">
            <header class="major">
                <h2>Additional info required</h2>
            </header>

            <form method="post" action="#">
                <div class="row gtr-uniform">
                    <div class="col-6 col-12-xsmall">
                        <input class="login_input" bind:value={name} type="text" placeholder="Name">
                    </div>
                    <div class="col-6 col-12-xsmall">
                        <input class="login_input" bind:value={company} type="text" placeholder="Company">
                    </div>
                    <div class="col-12 col-12-xsmall">
                        <input class="login_input" bind:value={phone} type="text" placeholder="Phone">
                    </div>
                    <div class="col-12">
                        <ul class="actions">
                            <li><input type="submit" on:click={handleCompleOAuth2Reg} value="Complete Registration" class="primary" /></li>
                        </ul>
                    </div>
                    <div class="col-12">
                        <p>{errorMsg}</p>
                    </div>
                </div>
            </form>
        </div>
    </div>
</section>



