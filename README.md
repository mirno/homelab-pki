<!-- Improved compatibility of back to top link: See: https://github.com/othneildrew/Best-README-Template/pull/73 -->
<a id="readme-top"></a>
<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![project_license][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]



<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/mirno/homelab-pki">
    <img src="https://www.gravatar.com/avatar/d2cebc82b2b5cec1b65e6c02a42c09d6?s=120&r=g&d=404" alt="Logo" width="80" height="80">
  </a>

<h3 align="center">homelab-pki</h3>

  <p align="center">
    project_description
    <br />
    <a href="https://github.com/mirno/homelab-pki"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/mirno/homelab-pki">View Demo</a>
    ·
    <a href="https://github.com/mirno/homelab-pki/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    ·
    <a href="https://github.com/mirno/homelab-pki/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

For the first project we will setup a custom CA provider. Based on an interface (usecases) it will implement certain functions we have defined. It will use an in Memory store by default (no persistence) for some quick testing.

Later on this should be improved using more persitent storage, ideally using in interface as well to provide locations to store this data for the Certificate authority.

Additional information on how to use [docker step-ca ](https://hub.docker.com/r/smallstep/step-ca).


<p align="right">(<a href="#readme-top">back to top</a>)</p>



### Built With

* [![Nix][Nix.com]][Nix-url]
* [DirEnv](https://direnv.net/)


<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started

### ACME

To explore with the [ACME protocol](https://datatracker.ietf.org/doc/html/rfc8555) we can decide to set this up ourselves. Or utilize `step-ca` as ACME server and `certbot` as ACME client.

### Prerequisites

Please use  [![Nix][Nix.com]][Nix-url]

Or check the [shell.nix](shell.nix) file and install the packages on your machine.

* List your tasks.
  ```task
  task -l
  ```

### Installation

1. Use [Taskfile](https://taskfile.dev/) or read the commands from [Taskfile.yml](Taskfile.yml)
2. Initialize CA and client
  ```sh
  step:init
  step:setup-client
  ```
3. Access the step-ca container and configure provisioners
  ```task
  docker exec -it step-ca-local  sh # `task step:shell`
    step ca provisioner add acme --type ACME
    step ca provisioner add acme-http --type ACME --challenge http-01
  ```
4. Get root CA for example purposes
  ```task
  step ca root .private/root_ca.crt
  task step:get-root-ca
  step --help
  curl https://localhost:9000/health # CA should be installed during `task step:setup-client`
  ```
5. Request a certificate using the client.
  Default this request a cn=localhost certificate in the .private/ folder. See the Taskfile summary to change dir and cn.

  ```task
  task step:generate:certificate
  ```

  Select te JWT provisioner if requested.
  Enter the [provisioner password](#provisioner-password) if required.

6. Certbot demo
  ```task
  task docker:certbot:init
  # or
  task compose:certbot:standalone:test
  ```
7. nginx demo
  ```task
  task compose:echo:up # nginx expects 'nginx' to be resolvable. If the step-ca-local contain is not running, then run `task step:up`
  task compose:certbot:webroot:init
  task verify:certificate HOST=nginx PORT=443 # verify the DNS name and date !
  task compose:certbot:renew   
  task compose:nginx:reload # reload the nginx config to install the new certificates without downtime.
  task verify:certificate HOST=nginx PORT=443 # verify the DNS name and date !
  ```

#### Troubleshooting

##### 'shared_network' not found when using docker
```shell
  docker network create shared_network
```

##### Environent variables missing.

Please enter those in `.env.local` to override.
```sh
echo "ENVIRONMENT=local" | tee .env.local
```

##### Provisioner password
Read the [smallstep-ca docker](https://hub.docker.com/r/smallstep/step-ca) page to figure out how to get the provisioner password.

```sh
  task step:shell 
    cat secrets/password
  docker run  -v step:/home/step smallstep/step-ca cat secrets/password
```

You can store the password file as well

```sh
  # Store secret in .private/secret
  docker run  -v step:/home/step smallstep/step-ca cat secrets/password | tee .private/secret
  chmod 600 .private/secret

  # Potentially modify the command yourself.
  step ca certificate --provisioner-password-file .private/secret
```

##### resolve hostnames

You might want to append the following to your hosts file `etc/hosts`
```
# custom
127.0.0.1   certbot
127.0.0.1   step-ca-local
127.0.0.1   echo
```

Alternatives are:
- dnsmasq
- coredns
- [HOSTALIASES](https://www.man7.org/linux/man-pages/man3/gethostbyname_r.3.html)



<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

Run your own Certificate authority at home, without depending on a online 3th party like Let's Encrypt.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ROADMAP -->
## Roadmap

- [ ] configure acme provisioners during `task step:init`
- [ ] ACME HTTP01 challange triggered certificate rotationcontainerized webserver using webroot
- [ ] CLI / Server with Interface in GOLANG
- [ ] ACME DNS01 challenge
    - [ ] DDNS requirements


See the [open issues](https://github.com/mirno/homelab-pki/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Top contributors:

<a href="https://github.com/mirno/homelab-pki/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=mirno/homelab-pki" alt="contrib.rocks image" />
</a>



<!-- LICENSE -->
## License

TODO:

Distributed under the project_license. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTACT -->
## Contact

Your Name - [@twitter_handle](https://twitter.com/twitter_handle) - email@email_client.com

Project Link: [https://github.com/mirno/homelab-pki](https://github.com/mirno/homelab-pki)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* []()
* []()
* []()

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/mirno/homelab-pki.svg?style=for-the-badge
[contributors-url]: https://github.com/mirno/homelab-pki/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/mirno/homelab-pki.svg?style=for-the-badge
[forks-url]: https://github.com/mirno/homelab-pki/network/members
[stars-shield]: https://img.shields.io/github/stars/mirno/homelab-pki.svg?style=for-the-badge
[stars-url]: https://github.com/mirno/homelab-pki/stargazers
[issues-shield]: https://img.shields.io/github/issues/mirno/homelab-pki.svg?style=for-the-badge
[issues-url]: https://github.com/mirno/homelab-pki/issues
[license-shield]: https://img.shields.io/github/license/mirno/homelab-pki.svg?style=for-the-badge
[license-url]: https://github.com/mirno/homelab-pki/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/linkedin_username
[product-screenshot]: images/screenshot.png
[Next.js]: https://img.shields.io/badge/next.js-000000?style=for-the-badge&logo=nextdotjs&logoColor=white
[Next-url]: https://nextjs.org/
[React.js]: https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB
[React-url]: https://reactjs.org/
[Vue.js]: https://img.shields.io/badge/Vue.js-35495E?style=for-the-badge&logo=vuedotjs&logoColor=4FC08D
[Vue-url]: https://vuejs.org/
[Angular.io]: https://img.shields.io/badge/Angular-DD0031?style=for-the-badge&logo=angular&logoColor=white
[Angular-url]: https://angular.io/
[Svelte.dev]: https://img.shields.io/badge/Svelte-4A4A55?style=for-the-badge&logo=svelte&logoColor=FF3E00
[Svelte-url]: https://svelte.dev/
[Laravel.com]: https://img.shields.io/badge/Laravel-FF2D20?style=for-the-badge&logo=laravel&logoColor=white
[Laravel-url]: https://laravel.com
[Bootstrap.com]: https://img.shields.io/badge/Bootstrap-563D7C?style=for-the-badge&logo=bootstrap&logoColor=white
[Bootstrap-url]: https://getbootstrap.com
[JQuery.com]: https://img.shields.io/badge/jQuery-0769AD?style=for-the-badge&logo=jquery&logoColor=white
[JQuery-url]: https://jquery.com
[Nix.com]: https://builtwithnix.org/badge.svg
[Nix-url]: https://builtwithnix.org