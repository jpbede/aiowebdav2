"""Response and request parsers/creator for WebDAV protocol."""

from io import BytesIO
from urllib.parse import unquote, urlparse, urlsplit

from lxml import etree

from .exceptions import MethodNotSupportedError, RemoteResourceNotFoundError
from .models import Property, PropertyRequest
from .urn import Urn


class WebDavXmlUtils:
    """WebDAV XML utils."""

    @staticmethod
    def parse_get_list_info_response(content: bytes) -> list[dict[str, str]]:
        """Parse of response content XML from WebDAV server and extract file and directory infos.

        :param content: the XML content of HTTP response from WebDAV server for getting list of files by remote path.
        :return: list of information, the information is a dictionary and it values with following keys:
                 `created`: date of resource creation,
                 `name`: name of resource,
                 `size`: size of resource,
                 `modified`: date of resource modification,
                 `etag`: etag of resource,
                 `content_type`: content type of resource,
                 `isdir`: type of resource,
                 `path`: path of resource.
        """
        try:
            tree = etree.fromstring(content)
            infos = []
            for response in tree.findall(".//{DAV:}response"):
                href_el = next(iter(response.findall(".//{DAV:}href")), None)
                if href_el is None:
                    continue
                path = unquote(urlsplit(href_el.text).path)
                is_dir = len(response.findall(".//{DAV:}collection")) > 0
                info = WebDavXmlUtils.get_info_from_response(response)
                info["isdir"] = str(is_dir)
                info["path"] = path
                infos.append(info)
        except etree.XMLSyntaxError:
            return []

        return infos

    @staticmethod
    def parse_get_list_property_response(
        content: bytes, properties: list[PropertyRequest], hostname: str
    ) -> dict[str, list[Property]]:
        """Parse of response content XML from WebDAV server and extract file and directory properties."""
        try:
            tree = etree.fromstring(content)
            properties_dict = {}
            for response in tree.findall(".//{DAV:}response"):
                href_el = next(iter(response.findall(".//{DAV:}href")), None)
                if href_el is None:
                    continue
                path = unquote(urlsplit(href_el.text).path)
                prefix = urlparse(hostname).path
                path = path.removeprefix(prefix)
                properties_dict[path] = WebDavXmlUtils.parse_get_properties_response(
                    etree.tostring(response), properties
                )
        except etree.XMLSyntaxError:
            return {}

        return properties_dict

    @staticmethod
    def parse_get_list_response(content: bytes) -> list[Urn]:
        """Parse of response content XML from WebDAV server and extract file and directory names.

        :param content: the XML content of HTTP response from WebDAV server for getting list of files by remote path.
        :return: list of extracted file or directory names.
        """
        try:
            tree = etree.fromstring(content)
            urns = []
            for response in tree.findall(".//{DAV:}response"):
                href_el = next(iter(response.findall(".//{DAV:}href")), None)
                if href_el is None:
                    continue
                href = Urn.separate + unquote(urlsplit(href_el.text).path)
                is_dir = len(response.findall(".//{DAV:}collection")) > 0
                urns.append(Urn(href, directory=is_dir))
        except etree.XMLSyntaxError:
            return []

        return urns

    @staticmethod
    def create_free_space_request_content() -> bytes:
        """Create an XML for requesting of free space on remote WebDAV server.

        :return: the XML string of request content.
        """
        root = etree.Element("propfind", xmlns="DAV:")
        prop = etree.SubElement(root, "prop")
        etree.SubElement(prop, "quota-available-bytes")
        etree.SubElement(prop, "quota-used-bytes")
        tree = etree.ElementTree(root)
        return WebDavXmlUtils.etree_to_string(tree)

    @staticmethod
    def parse_free_space_response(content: bytes, hostname: str) -> int | None:
        """Parse of response content XML from WebDAV server and extract an amount of free space.

        :param content: the XML content of HTTP response from WebDAV server for getting free space.
        :param hostname: the server hostname.
        :return: an amount of free space in bytes.
        """
        try:
            tree = etree.fromstring(content)
            node = tree.find(".//{DAV:}quota-available-bytes")
            if node is not None:
                return int(node.text)
            raise MethodNotSupportedError(name="free", server=hostname)
        except TypeError as err:
            raise MethodNotSupportedError(name="free", server=hostname) from err
        except etree.XMLSyntaxError:
            return None

    @staticmethod
    def get_info_from_response(response: etree.Element) -> dict[str, str]:
        """Get information attributes from response.

        :param response: XML object of response for the remote resource defined by path
        :return: a dictionary of information attributes and them values with following keys:
                 `created`: date of resource creation,
                 `name`: name of resource,
                 `size`: size of resource,
                 `modified`: date of resource modification,
                 `etag`: etag of resource,
                 `content_type`: content type of resource.
        """
        find_attributes = {
            "created": ".//{DAV:}creationdate",
            "name": ".//{DAV:}displayname",
            "size": ".//{DAV:}getcontentlength",
            "modified": ".//{DAV:}getlastmodified",
            "etag": ".//{DAV:}getetag",
            "content_type": ".//{DAV:}getcontenttype",
        }
        info = {}
        for name, value in find_attributes.items():
            info[name] = str(response.findtext(value)).strip()
        return info

    @staticmethod
    def parse_info_response(content: bytes, path: str, hostname: str) -> dict[str, str]:
        """Parse of response content XML from WebDAV server and extract an information about resource.

        :param content: the XML content of HTTP response from WebDAV server.
        :param path: the path to resource.
        :param hostname: the server hostname.
        :return: a dictionary of information attributes and them values with following keys:
                 `created`: date of resource creation,
                 `name`: name of resource,
                 `size`: size of resource,
                 `modified`: date of resource modification,
                 `etag`: etag of resource,
                 `content_type`: content type of resource.
        """
        response = WebDavXmlUtils.extract_response_for_path(
            content=content, path=path, hostname=hostname
        )
        return WebDavXmlUtils.get_info_from_response(response)

    @staticmethod
    def parse_is_dir_response(content: bytes, path: str, hostname: str) -> bool:
        """Parse of response content XML from WebDAV server and extract an information about resource.

        :param content: the XML content of HTTP response from WebDAV server.
        :param path: the path to resource.
        :param hostname: the server hostname.
        :return: True in case the remote resource is directory and False otherwise.
        """
        response = WebDavXmlUtils.extract_response_for_path(
            content=content, path=path, hostname=hostname
        )
        resource_type = response.find(".//{DAV:}resourcetype")
        if resource_type is None:
            raise MethodNotSupportedError(name="is_dir", server=hostname)
        dir_type = resource_type.find("{DAV:}collection")

        return dir_type is not None

    @staticmethod
    def create_get_property_batch_request_content(
        requested_properties: list[PropertyRequest],
    ) -> bytes:
        """Create an XML for requesting of getting a property value of remote WebDAV resource.

        :param requested_properties: the property attributes as dictionary with following keys:
                       `namespace`: (optional) the namespace for XML property which will be get,
                       `name`: the name of property which will be get.
        :return: the XML string of request content.
        """
        root = etree.Element("propfind", xmlns="DAV:")
        prop = etree.SubElement(root, "prop")
        for requested_property in requested_properties:
            etree.SubElement(
                prop, requested_property.name, xmlns=requested_property.namespace
            )
        tree = etree.ElementTree(root)
        return WebDavXmlUtils.etree_to_string(tree)

    @staticmethod
    def parse_get_properties_response(
        content: bytes, requested_properties: list[PropertyRequest]
    ) -> list[Property]:
        """Parse of response content XML from WebDAV server for getting metadata property value for some resource.

        :param content: the XML content of response as string.
        :param requested_properties: the requested property as list
        :return: the value of property if it has been found or None otherwise.
        """
        tree = etree.fromstring(content)
        return [
            Property(
                name=requested_property.name,
                namespace=requested_property.namespace,
                value=value,
            )
            for requested_property in requested_properties
            if (
                value := WebDavXmlUtils.get_property_value(
                    tree, requested_property.name
                )
            )
        ]

    @staticmethod
    def get_property_value(tree: etree.Element, name: str) -> str | None:
        """Get property value from XML tree.

        :param tree: the XML tree.
        :param name: the name of property for finding a value in response
        :return: the value of property if it has been found or None otherwise.
        """
        xpath = "//*[local-name() = $name]"
        return (
            tree.xpath(xpath, name=name)[0].text
            if tree.xpath(xpath, name=name)
            else None
        )

    @staticmethod
    def create_set_property_batch_request_content(properties: list[Property]) -> bytes:
        """Create an XML for requesting of setting a property values for remote WebDAV resource in batch.

        :param properties: the property attributes as list of dictionaries with following keys:
               `namespace`: (optional) the namespace for XML property which will be set,
               `name`: the name of property which will be set,
               `value`: (optional) the value of property which will be set. Defaults is empty string.
        :return: the XML string of request content.
        """
        root_node = etree.Element("propertyupdate", xmlns="DAV:")
        set_node = etree.SubElement(root_node, "set")
        prop_node = etree.SubElement(set_node, "prop")
        for prop in properties:
            opt_node = etree.SubElement(prop_node, prop.name, xmlns=prop.namespace)
            opt_node.text = prop.value
        tree = etree.ElementTree(root_node)
        return WebDavXmlUtils.etree_to_string(tree)

    @staticmethod
    def etree_to_string(tree: etree.ElementTree) -> bytes:
        """Create string from lxml.etree.ElementTree with XML declaration and UTF-8 encoding.

        :param tree: the instance of ElementTree
        :return: the string of XML.
        """
        buff = BytesIO()
        tree.write(buff, xml_declaration=True, encoding="UTF-8")
        return buff.getvalue()

    @staticmethod
    def extract_response_for_path(
        content: bytes, path: str, hostname: str
    ) -> etree.Element:
        """Extract single response for specified remote resource.

        :param content: raw content of response as string.
        :param path: the path to needed remote resource.
        :param hostname: the server hostname.
        :return: XML object of response for the remote resource defined by path.
        """
        prefix = urlparse(hostname).path
        try:
            tree = etree.fromstring(content)
            responses = tree.findall("{DAV:}response")
            n_path = Urn.normalize_path(path)

            for resp in responses:
                href = resp.findtext("{DAV:}href")
                if Urn.compare_path(n_path, href) or Urn.compare_path(
                    n_path, href.removeprefix(prefix)
                ):
                    return resp
            raise RemoteResourceNotFoundError(path)
        except etree.XMLSyntaxError as err:
            raise MethodNotSupportedError(name="is_dir", server=hostname) from err
