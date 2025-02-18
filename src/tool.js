const { Bls12381G2KeyPair } = require("./signature/index");

async function createIssuerKey(_publicKeyId, _issuerId) {
  const myLdKey = await Bls12381G2KeyPair.generate({
    id: _publicKeyId,
    controller: _issuerId
  })
  var keyPairOptions = {}
  keyPairOptions["id"] = _publicKeyId
  keyPairOptions["controller"] = _issuerId
  keyPairOptions["publicKeyBase58"] = myLdKey.publicKey
  keyPairOptions["privateKeyBase58"] = myLdKey.privateKey
  return keyPairOptions
}

function createVocab(template, templateName, items, url) {
  template["@context"][templateName] = require("../data/attributeTemplate.json")
  template["@context"][templateName]["@id"] = url
  for(var item in items){
    if(items[item]=="int"){
      template["@context"][templateName]["@context"][item]={"@id": "test:"+item,"@type": "xsd:int"}
    }else if (items[item]=="dateTime"){
      template["@context"][templateName]["@context"][item]={"@id": "test:"+item,"@type": "xsd:dateTime"}
    }else if (items[item]=="decimal"){
      template["@context"][templateName]["@context"][item]={"@id": "test:"+item,"@type": "xsd:decimal"}
    }else {
      template["@context"][templateName]["@context"][item]={"@id": "test:"+item,"@type": "xsd:normalizedString"}
    }
  }
  template["@context"][templateName]["@context"]["id"] = "@id"
  return template
}


function createControllerDoc(template, issuerId, publicKeyId) {
  template.id = issuerId
  template.assertionMethod.push(publicKeyId)
  return template
}


function createInputDocument(vocabUrl, templateName, issuerId, attributes) {
  template = require("../data/inputDocument.json")
  template["@context"].push(vocabUrl)
  template.credentialSubject.type.push(templateName)
  template.issuer = issuerId
  for (var item in attributes) {
    template.credentialSubject[item] = attributes[item]
  }
  issueTime = new Date()
  expireTime = new Date()
  expireTime.setMonth(issueTime.getMonth() + 1)
  template.issuanceDate = issueTime
  template.expirationDate = expireTime
  identifier = Math.round(Math.random() * 100000)
  template.identifier = identifier
  template.id = template.id + identifier
  return template
}

module.exports = {
  createInputDocument,
  createControllerDoc,
  createIssuerKey,
  createVocab
}
