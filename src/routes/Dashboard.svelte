<script>
    import {ensureUserIsLoggedIn} from '../lib/User.api'

    ensureUserIsLoggedIn()
</script>

<section id="first" class="main special">
    <header class="major">
        <h2>Choose your test suit</h2>
    </header>
    <ul class="features">
        <li>
            <span class="icon solid major style1 fa fa-robot"></span>
            <h3>Device tests (Coming soon)</h3>
            <p>Testing device for support of TO1 and TO2 protocols</p>
            <!-- <a href="/#/test/device" class="button">Run</a> -->

        </li>
        <li>
            <span class="icon solid major style3 fa fa-database"></span>
            <h3>Rendezvous Server tests</h3>
            <p>Testing RV for support of TO0 and TO1 protocols</p>
            <a href="/#/test/rv" class="button">Run</a>
        </li>
        <li>
            <span class="icon solid major style5 fa fa-cogs"></span>
            <h3>Device Onboarding service (Coming soon)</h3>
            <p>Testing DO for support of TO0 and TO2 protocols</p>
            <a href="/#/test/do" class="button">Run</a>
        </li>
    </ul>
</section>