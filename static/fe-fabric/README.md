# FireEye Styleguide - FE-Fabricv2

## Table of contents

* [Development](#development)
* [Build](#build)
* [Documentation](#documentation)
* [Contribute](#contribute)

### Development

#### Set-up
1. On your favourite browser, open <https://ghe.eng.fireeye.com/fabric-community/fe-fabricv2>.
2. *Recommended:* Fork this repository *(Use the ```Fork``` button on right top corner)*
3. On your local machine, clone this fork <br/>```git clone https://ghe.eng.fireeye.com/user-name/fe-fabricv2.git```
4. ```cd fe-fabricv2```
5. ```git remote add upstream https://ghe.eng.fireeye.com/fabric-community/fe-fabricv2.git```
6. ```git remote -v```<br/>This should return something like this -
```
origin  https://ghe.eng.fireeye.com/user-name/fe-fabricv2.git (fetch)
origin  https://ghe.eng.fireeye.com/user-name/fe-fabricv2.git (push)
upstream  https://ghe.eng.fireeye.com/fabric-community/fe-fabricv2.git (push)
upstream  https://ghe.eng.fireeye.com/fabric-community/fe-fabricv2.git (fetch)
```

#### Commits
*These are just guidelines*

1. For every feature/bug, create a new branch <br/>
```git checkout -b feature/feature_name```
2. Make requisite changes
3. You are now ready to make your first commit <br/>
```git add filename```<br/>
```git commit –m “[#issue] text”```<br/>
```git push origin feature/feature_name```<br/>
4. Create a pull request for the commit just made.<br/>
    *Browse to <https://ghe.eng.fireeye.com/user-name/fe-fabricv2/branches> and for branch feature/feature_name click ```New pull request``` button*
5. Once reviewed, repository owners shall merge the changes.

### Build

```
npm install
npm start
```
### Documentation

FEYE Fabric's documentation, included in this repo in the root directory, is built with [Jekyll](http://jekyllrb.com)

### Running documentation locally

1. If necessary, [install Jekyll](http://jekyllrb.com/docs/installation) (requires v2.5.x).
   **Note for Windows users:** Read [this unofficial guide](http://jekyll-windows.juthilo.com/) to get Jekyll up and running without problems.
2. Install the Ruby-based syntax highlighter, [Rouge](https://github.com/jneen/rouge), with `gem install rouge`.
3. From the root `/fe-fabricv2` directory, run `npm install` then `npm run build` in the command line.
4. Open `http://localhost:8000` in your browser, and voilà.

Learn more about using Jekyll by reading its [documentation](http://jekyllrb.com/docs/home/).

### Contribute

1. Fork repo
2. Clone your repo locally
3. Add main repo as upstream
4. Create feature branch locally
5. Push branch to your repo
6. Create Pull Request from your repo/branch to main repo/develop

### Learn

#### BEM
* https://en.bem.info/
