from re import search
from requests import post, Response
from tplinkrouterc6u.common.encryption import EncryptionWrapper
from tplinkrouterc6u.common.exception import ClientException, AuthorizeError
from tplinkrouterc6u.client.c6u import TplinkRouter


class TplinkA20Router(TplinkRouter):
    username = ""
    password = ""
    _pwdNN = ""
    _pwdEE = ""
    _encryption = EncryptionWrapper()

    def supports(self) -> bool:
        if len(self.password) > 125:
            return False

        try:
            self._request_pwd()
            return True
        except ClientException:
            return False

    def authorize(self) -> None:
        if self._pwdNN == "":
            self._request_pwd()

        response = self._try_login()

        data = response.text
        try:
            data = response.json()
            self._stok = data[self._data_block]["stok"]
            regex_result = search("sysauth=(.*);", response.headers["set-cookie"])
            self._sysauth = regex_result.group(1)
            self._logged = True

        except Exception as e:
            error = "TplinkRouter - A20 - Cannot authorize! Error - {}; Response - {}".format(
                e, data
            )
            if self._logger:
                self._logger.debug(error)
            if "data" in vars() and data.get("errorcode") == "login failed":
                raise AuthorizeError(error)
            raise ClientException(error)

    def _request_pwd(self) -> None:
        url = "{}/cgi-bin/luci/;stok=/login?form=login".format(self.host)
        response = post(
            url,
            params={"operation": "read"},
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        try:
            data = response.json()

            args = data[self._data_block]["password"]

            self._pwdNN = args[0]
            self._pwdEE = args[1]

        except Exception as e:
            error = "TplinkRouter - A20 - {} - Unknown error for pwd! Error - {}; Response - {}".format(
                self.__class__.__name__, e, response.text
            )
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def _try_login(self) -> Response:
        url = "{}/cgi-bin/luci/;stok=/login?form=cloud_login".format(self.host)

        crypted_pwd = self._encryption.rsa_encrypt(
            self.password, self._pwdNN, self._pwdEE
        )

        body = {
            "operation": "login",
            "username": self.username,
            "password": crypted_pwd,
        }

        return post(
            url,
            data=body,
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )
