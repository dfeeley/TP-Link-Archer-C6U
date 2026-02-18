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

    def logout(self) -> None:
        self.request(
            "admin/system?form=logout",
            data={"operation": "write"},
            ignore_response=True,
        )

    def get_status(self):
        return self.request("admin/status?form=all", data={"operation": "read"})

    def get_parental_controls_list(self):
        return self.request(
            "admin/smart_network?form=patrol_owner_list", data={"operation": "load"}
        )

    def block_internet(self, profile_id: int, block: bool):
        return self.request(
            "admin/smart_network?form=patrol_owner_block",
            data={
                "operation": "write",
                "owner_id": profile_id,
                "internet_blocked": block,
            },
            ignore_response=True,
        )

    def request(
        self,
        path: str,
        data: str,
        ignore_response: bool = False,
        ignore_errors: bool = False,
    ) -> dict | None:
        if self._logged is False:
            raise Exception("Not authorised")
        url = "{}/cgi-bin/luci/;stok={}/{}".format(self.host, self._stok, path)

        response = post(
            url,
            data=data,
            headers=self._headers_request,
            cookies={"sysauth": self._sysauth},
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

        if ignore_response:
            return None

        data = response.text
        error = ""
        try:
            data = response.json()
            if "data" not in data:
                raise Exception("Router didn't respond with JSON")

            if self._is_valid_response(data):
                return data.get(self._data_block)
            elif ignore_errors:
                return data
        except Exception as e:
            error = "TplinkRouter - {} - An unknown response - {}; Request {} - Response {}".format(
                self.__class__.__name__, e, path, data
            )
        error = (
            (
                "TplinkRouter - {} - Response with error; Request {} - Response {}".format(
                    self.__class__.__name__, path, data
                )
            )
            if not error
            else error
        )
        if self._logger:
            self._logger.debug(error)
        raise ClientException(error)

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
            "confirm": "true",  # if existing login, confirm force them out
        }

        return post(
            url,
            data=body,
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )
