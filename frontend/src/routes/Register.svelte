<script lang="ts">
    import svelteLogo from '../assets/FIDO_Alliance_logo_black_RGB.webp'
    import {register} from '../lib/User.api'
    import {push} from "svelte-spa-router"

    let email: string = ""
    let password: string = ""
    let passwordRepeat: string = ""
    let name: string = ""
    let company: string = ""
    let phone: string = ""
    let errorMsg: string = ""

    const handleRegister = async (e) => {
        e.preventDefault()
        errorMsg = ""

        await register(password, passwordRepeat, email, company, name, phone)
        .then(() => {
            errorMsg = "Successfully registered"
            window.setTimeout(() => push("/test"), 1500)
        })
        .catch((err) => {
            errorMsg = err
        })
    }
</script>

<style>
    .fidologo {
        border: none;
        border-radius: 0% !important;
    }
</style>


<section id="intro" class="main">
    <div class="spotlight">
        <div class="content">
            <header class="major">
                <h2>Register</h2>
            </header>

            <form method="post" action="#">
                <div class="row gtr-uniform">
                    <div class="col-6 col-12-xsmall">
                        <input class="login_input" bind:value={name} type="text" placeholder="Name">
                    </div>
                    <div class="col-6 col-12-xsmall">
                        <input class="login_input" bind:value={email} type="email" placeholder="Email">
                    </div>
                    <div class="col-6 col-12-xsmall">
                        <input class="login_input" bind:value={company} type="text" placeholder="Company">
                    </div>
                    <div class="col-6 col-12-xsmall">
                        <input class="login_input" bind:value={phone} type="text" placeholder="Phone">
                    </div>
                    <div class="col-6 col-12-xsmall">
                        <input class="login_input" bind:value={password} type="password" placeholder="Password">
                    </div>
                    <div class="col-6 col-12-xsmall">
                        <input class="login_input" bind:value={passwordRepeat} type="password" placeholder="Confirm your password">
                    </div>
                    <div class="col-12">
                        <ul class="actions">
                            <li><input type="submit" on:click={handleRegister} value="Register" class="primary" /></li>
                        </ul>
                    </div>
                    <div class="col-12">
                        <p>{errorMsg}</p>
                    </div>
                </div>
            </form>
        </div>
        <span class="image fidologo"><img src={svelteLogo} class="fidologo" alt="FIDO Logo" /></span>
    </div>
</section>



